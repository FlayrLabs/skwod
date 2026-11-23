package io.skwod.app

import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat

/**
 * The persistent connection. Android has no way to wake a sleeping app without Google's FCM, and
 * skwod uses neither FCM nor a push gateway on Android — so while the user is signed in, this
 * foreground service keeps the process (and with it the p2p session, the WebSocket and the E2EE
 * inbox sync that [AppModel] owns) alive. Incoming messages are decrypted on the device and shown
 * as local notifications; an incoming call rings with a full-screen notification.
 *
 * Type `remoteMessaging`: unlike `dataSync` it has no 6-hour daily cap on Android 15 and may be
 * started from BOOT_COMPLETED. The notification is silent and minimal.
 */
class ConnectionService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val model = AppModel.get(this)
        val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING else 0
        try {
            ServiceCompat.startForeground(this, Notifications.ID_CONNECTION,
                Notifications.connection(this, model.connection.title), type)
        } catch (_: Exception) {
            // Started from a state where a foreground service isn't allowed (Android 12+
            // background start). Nothing to keep alive; the next app open starts it again.
            stopSelf(); return START_NOT_STICKY
        }
        running = true
        // Started by boot / app update / a sticky restart with no activity: bring the session up.
        model.launchIO {
            if (!model.restoreOnce()) { stopSelf() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        super.onDestroy()
    }

    companion object {
        @Volatile var running = false
            private set

        /** Start (or keep) the connection service if the user is signed in and wants it. */
        fun sync(ctx: Context) {
            val app = ctx.applicationContext
            val wanted = AppSettings.get(app).keepConnected && AppModel.get(app).workspaces.isNotEmpty()
            if (!wanted) { stop(app); return }
            try { ContextCompat.startForegroundService(app, Intent(app, ConnectionService::class.java)) } catch (_: Exception) {}
        }

        /** Used at boot, before the model has loaded anything: start and let the service decide. */
        fun startUnconditionally(ctx: Context) {
            val app = ctx.applicationContext
            if (!AppSettings.get(app).keepConnected) return
            try { ContextCompat.startForegroundService(app, Intent(app, ConnectionService::class.java)) } catch (_: Exception) {}
        }

        fun stop(ctx: Context) {
            try { ctx.applicationContext.stopService(Intent(ctx.applicationContext, ConnectionService::class.java)) } catch (_: Exception) {}
        }

        /** Refresh the status line ("Connected directly", "Host is offline", …). */
        fun updateStatus(ctx: Context, status: String) {
            if (!running) return
            try { NotificationManagerCompat.from(ctx).notify(Notifications.ID_CONNECTION, Notifications.connection(ctx, status)) }
            catch (_: SecurityException) {}
        }

        /** Doze suspends network access even for a foreground service unless the app is exempt. */
        fun isBatteryExempt(ctx: Context): Boolean {
            val pm = ctx.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return false
            return pm.isIgnoringBatteryOptimizations(ctx.packageName)
        }

        /** The system's own yes/no dialog for the exemption. Only called after we explained why. */
        fun requestBatteryExemption(ctx: Context) {
            val direct = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${ctx.packageName}"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            try { ctx.startActivity(direct) } catch (_: Exception) {
                try {
                    ctx.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                } catch (_: Exception) {}
            }
        }
    }
}

/**
 * Foreground service for the duration of a call, so the microphone/camera keep working when the
 * user switches apps or the screen turns off. Started from the call screen (app in front, which
 * the while-in-use types require) and stopped when the call ends.
 */
class CallService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        var type = 0
        if (Build.VERSION.SDK_INT >= 30) {
            type = ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL
            if (granted(android.Manifest.permission.RECORD_AUDIO)) type = type or ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            if (granted(android.Manifest.permission.CAMERA)) type = type or ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA
        }
        try {
            ServiceCompat.startForeground(this, Notifications.ID_ONGOING_CALL, Notifications.ongoingCall(this), type)
        } catch (_: Exception) {
            // The call itself still works while the app is in front; only backgrounding suffers.
            stopSelf()
        }
        return START_NOT_STICKY
    }

    private fun granted(p: String) = ContextCompat.checkSelfPermission(this, p) == PackageManager.PERMISSION_GRANTED

    companion object {
        fun start(ctx: Context) {
            try { ContextCompat.startForegroundService(ctx.applicationContext, Intent(ctx.applicationContext, CallService::class.java)) } catch (_: Exception) {}
        }
        fun stop(ctx: Context) {
            try { ctx.applicationContext.stopService(Intent(ctx.applicationContext, CallService::class.java)) } catch (_: Exception) {}
        }
    }
}

/** Bring the connection back after a reboot or an app update (both may start a foreground service). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED -> ConnectionService.startUnconditionally(context)
        }
    }
}

/** Buttons on the call notifications. Not exported; reached only by this app's PendingIntents. */
class NotificationActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Notifications.ACTION_DECLINE -> {
                Notifications.cancelIncomingCall(context)
                AppModel.get(context).incomingCall = null
            }
            Notifications.ACTION_HANGUP -> CallState.requestHangup()
        }
    }
}

/** Whether a call is up, and a way for the notification's hang-up button to end it. */
object CallState {
    val active = androidx.compose.runtime.mutableStateOf(false)
    val hangupRequests = androidx.compose.runtime.mutableIntStateOf(0)
    fun requestHangup() { hangupRequests.intValue = hangupRequests.intValue + 1 }
    /**
     * Who is speaking in the call THIS phone is in (build 47): (server id, user ids). The
     * sidebar's green ring. Nobody else's call is known here — the server never sees speech.
     */
    val speaking = androidx.compose.runtime.mutableStateOf("" to emptySet<String>())
}
