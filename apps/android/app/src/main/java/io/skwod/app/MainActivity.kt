package io.skwod.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private val askNotifications =
        registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.RequestPermission()) {
            ConnectionService.sync(this)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        ScreenPrivacy.apply(this)          // recents privacy / FLAG_SECURE before anything is drawn
        // This activity shows chats: it must NEVER appear over the lock screen. (Only
        // IncomingCallActivity may, and it shows nothing but the caller and two buttons.)
        if (android.os.Build.VERSION.SDK_INT >= 27) { setShowWhenLocked(false); setTurnScreenOn(false) }
        val model = AppModel.get(this)
        Notifications.ensureChannels(this)
        handleIntent(intent)
        // Local notifications (messages decrypted on this device, incoming calls) and the
        // foreground-service notification need POST_NOTIFICATIONS on Android 13+.
        if (android.os.Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
                android.content.pm.PackageManager.PERMISSION_GRANTED) {
            askNotifications.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }
        // Present as offline the moment the app is backgrounded/closed (and online again on return),
        // instead of waiting out the server's 3-minute stale window. Returning to the foreground
        // also re-probes the p2p path and re-dials a host that was offline.
        // (The process-wide foreground/background observer lives in AppModel, because the process
        // also runs with no activity at all — started at boot by the connection service.)
        setContent {
            SkwodTheme {
                // The frosted-glass backdrop lives at the root; Surface is transparent over it so
                // every screen shares the same glass (mirrors iOS SkwodBackground-at-window level).
                // The glow fills the whole window (behind the status + nav bars), but content is
                // inset by the system bars so it never bleeds under the clock/battery or the home
                // indicator (enableEdgeToEdge draws edge-to-edge; we consume the insets here).
                GlassScreen {
                Surface(
                    Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.systemBars),
                    color = androidx.compose.ui.graphics.Color.Transparent
                ) {
                    var phase by remember { mutableStateOf(Phase.Loading) }
                    var entitled by remember { mutableStateOf(false) }

                    LaunchedEffect(Unit) {
                        val restored = withContext(Dispatchers.IO) { model.restoreOnce() }
                        // The screen-security default was settled while restoring (new installs
                        // start with screenshots blocked): apply it to this window.
                        ScreenPrivacy.apply(this@MainActivity)
                        phase = if (!restored) Phase.Auth
                        else {
                            entitled = model.entitlement()
                            Phase.Gated
                        }
                    }

                    // DEBUG-only automation (a no-op stub in release). Started here rather than in
                    // a screen so it keeps running across the lock screen and the stopped states.
                    LaunchedEffect(Unit) { E2E.drive(model, applicationContext) }

                    // The app lock: while it is closed the lock screen is the ONLY thing
                    // composed — no chat, notice, dialog or sheet exists behind it.
                    if (AppLock.locked) {
                        LockScreen()
                        return@Surface
                    }

                    // Security events are never silent: safety-number changes, new devices, the
                    // protocol upgrade, "update required".
                    model.securityNotice?.let { (title, message) ->
                        val action = model.noticeAction
                        androidx.compose.material3.AlertDialog(
                            // Dismissing shows the NEXT queued notice: none is ever dropped.
                            onDismissRequest = { model.dismissNotice() },
                            confirmButton = {
                                if (action != null) androidx.compose.material3.TextButton(onClick = { model.performNoticeAction() }) { androidx.compose.material3.Text(action.label) }
                                else androidx.compose.material3.TextButton(onClick = { model.dismissNotice() }) { androidx.compose.material3.Text("OK") }
                            },
                            dismissButton = if (action != null) ({ androidx.compose.material3.TextButton(onClick = { model.dismissNotice() }) { androidx.compose.material3.Text("Not now") } }) else null,
                            title = { androidx.compose.material3.Text(title) },
                            text = { androidx.compose.material3.Text(message) },
                        )
                    }
                    // A tapped invite for a skwod we are already in: ask before joining anything.
                    model.confirmJoin?.let { join ->
                        androidx.compose.material3.AlertDialog(
                            onDismissRequest = { model.confirmJoin = null },
                            confirmButton = { androidx.compose.material3.TextButton(onClick = { model.acceptPendingJoin() }) { androidx.compose.material3.Text("Join") } },
                            dismissButton = { androidx.compose.material3.TextButton(onClick = { model.confirmJoin = null }) { androidx.compose.material3.Text("Not now") } },
                            title = { androidx.compose.material3.Text("Join a server in ${join.skwodName}?") },
                            text = { androidx.compose.material3.Text("The link you opened is an invite to a server in ${join.skwodName}, a skwod you are already signed in to. Joining asks its members for that server's keys with your account there. Only join if you trust where the link came from.") },
                        )
                    }
                    // Setting this install up (link / restore / reset), a waiting restore, the
                    // PIN, a restore elsewhere asking for an answer, the recovery-key flow.
                    if (phase == Phase.Gated) io.skwod.app.AccountPrompts()

                    // Signed out of the last skwod (or erased it): back to the log-in screen.
                    val leftEverything = { if (model.current == null) phase = Phase.Auth }

                    when (phase) {
                        Phase.Loading -> Splash()
                        Phase.Auth -> AuthScreen(
                            onDone = {
                                phase = Phase.Gated
                                entitled = model.entitlement()
                            }
                        )
                        Phase.Gated -> {
                            // No paywall by default: nothing checks billing and nothing gates the
                            // app. The Play-subscription gate only exists when the build was made
                            // with -Pskwod.paywall=true (BuildConfig.SKWOD_PAYWALL).
                            LaunchedEffect(Unit) { entitled = model.entitlement() }
                            val stopped = model.stopped
                            when {
                                // Removed from the account, or superseded by a restore elsewhere:
                                // that state is shown IN PLACE of the app.
                                stopped != null -> io.skwod.app.DeviceStoppedScreen(stopped, onSignedOut = leftEverything)
                                !BuildConfig.SKWOD_PAYWALL || entitled -> MainScreen(onSignOut = leftEverything)
                                else -> PaywallGate.Screen(
                                    onRefresh = { entitled = model.entitlement() },
                                    onSignOut = { model.signOut(); phase = Phase.Auth }
                                )
                            }
                        }
                    }
                }
                }
            }
        }
    }

    @Deprecated("The Android 8 / 9 confirm-credential screen answers here; newer releases use the biometric prompt's callback.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        AppLock.onCredentialResult(requestCode, resultCode)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        ScreenPrivacy.apply(this)
    }

    /**
     * Everything that can arrive from outside. The activity is exported, so every field is
     * untrusted: a VIEW intent's data is only accepted if it parses as an invite, and it only ever
     * prefills the connect screen. The app's own actions are honoured only when the intent carries
     * this process's nonce (i.e. it came from one of our PendingIntents); anything else is treated
     * as a plain launch. Nothing here ever shows the activity over the lock screen.
     */
    private fun handleIntent(intent: Intent?) {
        intent ?: return
        val model = AppModel.get(this)
        when (intent.action) {
            Intent.ACTION_VIEW -> {
                val raw = intent.dataString ?: return
                // Only the two invite spellings: skwod://join/… and (app link) https://skwod.io/join#…
                if (raw.length > InviteLink.MAX_LENGTH ||
                    !(raw.startsWith(InviteLink.P2P_PREFIX, ignoreCase = true) || InviteLink.isOnShareOrigin(raw))) return
                try { InviteLink.parse(raw) } catch (_: InviteException) { return }
                // Never joins by itself: a link for a skwod we are in asks first; any other
                // prefills the connect screen.
                model.handleIncomingLink(raw)
            }
            Notifications.ACTION_OPEN -> {
                // Tapping a message / status notification: just come to the front. Honoured only
                // from our own PendingIntent; it carries nothing that changes state.
                if (!IntentGuard.isOurs(intent.getStringExtra(IntentGuard.EXTRA_NONCE))) return
            }
            // Calls are answered through IncomingCallActivity (which unlocks first), never here.
        }
        // An intent is handled once; a rotation must not replay it.
        intent.action = Intent.ACTION_MAIN
        intent.data = null
    }
}

enum class Phase { Loading, Auth, Gated }
