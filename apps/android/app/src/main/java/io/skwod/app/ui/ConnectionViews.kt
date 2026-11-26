package io.skwod.app

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CallEnd
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat

/**
 * The always-visible connection indicator: a coloured dot + a few words; tap for the one-sentence
 * explanation. Deliberately free of jargon — "directly" vs "through a relay" is the whole story.
 */
@Composable
fun ConnectionPill(modifier: Modifier = Modifier, compact: Boolean = false) {
    val model = AppModel.get(LocalContext.current)
    if (model.current == null) return
    P2PManager.quality.value            // observe: recompose when the path changes
    val q = model.connection
    var showDetail by remember { mutableStateOf(false) }
    Row(modifier.clip(RoundedCornerShape(50)).background(Color.White.copy(alpha = 0.07f))
        .clickable { showDetail = true }.padding(horizontal = if (compact) 6.dp else 10.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(q.color))
        if (!compact) {
            Spacer(Modifier.width(6.dp))
            Text(q.title, color = Color.White.copy(alpha = 0.75f), fontSize = 11.sp, fontWeight = FontWeight.Medium, maxLines = 1)
        }
    }
    if (showDetail) {
        AlertDialog(
            onDismissRequest = { showDetail = false },
            confirmButton = { TextButton(onClick = { showDetail = false }) { Text("OK") } },
            title = { Text(q.title, color = q.color) },
            text = {
                Column {
                    Text(q.detail)
                    if (q.rtt > 0) {
                        Spacer(Modifier.height(8.dp))
                        Text("Response time: ${q.rtt} ms", style = MaterialTheme.typography.labelSmall, color = Color.White.copy(alpha = 0.6f))
                    }
                }
            }
        )
    }
}

/** The header the conversation screens draw at their top (16 dp of padding and a 48 dp row). */
internal val SCREEN_HEADER = 64.dp

/** Whether the [ConnectionBanner] is up. */
@Composable
internal fun connectionStripShowing(model: AppModel): Boolean {
    P2PManager.quality.value
    return model.current != null && !model.connection.isUsable
}

/** Relays are off and there is no direct way to the host: what would help, at the user's tap. */
@Composable
private fun DirectOnlyNotice(model: AppModel, modifier: Modifier) {
    var asking by remember { mutableStateOf(false) }
    Surface(color = Color(0xFF1B1B26), shape = RoundedCornerShape(18.dp), modifier = modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 9.dp)) {
            Text(DirectOnlyRule.text(model.current?.displayName ?: "your host"), color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
            Row {
                TextButton(onClick = { asking = true }) { Text("Turn on", color = SkAccent, fontWeight = FontWeight.SemiBold) }
                TextButton(onClick = { model.retryConnection() }) { Text("Retry", color = SkAccent, fontWeight = FontWeight.SemiBold) }
            }
        }
    }
    if (asking) AlertDialog(onDismissRequest = { asking = false }, title = { Text("Allow relays?") }, text = { Text(DirectOnlyRule.WHAT_A_RELAY_SEES) },
        confirmButton = { TextButton(onClick = { asking = false; model.useRelayWhenNeeded() }) { Text("Turn on") } },
        dismissButton = { TextButton(onClick = { asking = false }) { Text("Cancel") } })
}

/**
 * A strip across the top of the app while the active skwod can't be reached — so a message that
 * isn't sending is never a mystery. Hidden whenever the connection is usable.
 */
@Composable
fun ConnectionBanner(modifier: Modifier = Modifier) {
    val model = AppModel.get(LocalContext.current)
    if (!connectionStripShowing(model)) return
    val q = model.connection
    if (model.cannotReachDirectly) { DirectOnlyNotice(model, modifier); return }
    Surface(color = Color(0xFF1B1B26), shape = RoundedCornerShape(50), modifier = modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
        Row(Modifier.padding(horizontal = 14.dp, vertical = 9.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(9.dp).clip(CircleShape).background(q.color))
            Spacer(Modifier.width(8.dp))
            Column {
                Text(q.title, color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                if (q == ConnectionQuality.Offline) {
                    Text("Their computer may be off or asleep. Skwod keeps trying.", color = Color.White.copy(alpha = 0.6f), fontSize = 11.sp)
                }
            }
            if (q == ConnectionQuality.Offline) {
                Spacer(Modifier.width(8.dp))
                TextButton(onClick = { model.retryConnection() }) { Text("Retry", color = SkAccent, fontWeight = FontWeight.SemiBold) }
            }
        }
    }
}

@Composable
private fun SettingRow(title: String, detail: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, color = Color.White)
            Text(detail, color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
        }
        Spacer(Modifier.width(10.dp))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

/** Settings → the automatic daily update check ([Updater.autoCheck]). On by default. */
@Composable
fun UpdateSettingRow() {
    val ctx = LocalContext.current
    val model = AppModel.get(ctx)
    val settings = model.settings
    SettingRow("Check for updates automatically",
        "Once a day Skwod asks GitHub, where its releases are published, whether a new version is out. GitHub sees your IP address and nothing else. Installing always takes your tap.",
        settings.autoUpdateCheck) { v ->
        settings.autoUpdateCheck = v
        if (v) model.launchIO { Updater.autoCheck(ctx.applicationContext) }
    }
}

/**
 * Profile → Privacy & notifications: how we're connected, relays, staying connected in the
 * background (and the battery exemption that needs), notification previews, screen privacy.
 */
@Composable
fun PrivacySection() {
    val ctx = LocalContext.current
    val model = AppModel.get(ctx)
    val settings = model.settings
    val scope = rememberCoroutineScope()
    var explainBattery by remember { mutableStateOf(false) }
    var exempt by remember { mutableStateOf(ConnectionService.isBatteryExempt(ctx)) }
    val notifPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
    val lifecycleOwner = androidx.compose.ui.platform.LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val obs = androidx.lifecycle.LifecycleEventObserver { _, e ->
            if (e == androidx.lifecycle.Lifecycle.Event.ON_RESUME) exempt = ConnectionService.isBatteryExempt(ctx)
        }
        lifecycleOwner.lifecycle.addObserver(obs)
        onDispose { lifecycleOwner.lifecycle.removeObserver(obs) }
    }

    Text("Privacy & notifications", color = Color.White, style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(8.dp))
    AppLockSetting()
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text("Connection", color = Color.White, modifier = Modifier.weight(1f))
        ConnectionPill()
    }
    if (model.current?.isP2P == true) {
        SettingRow("Allow relays",
            "When no direct route to your host exists, a relay passes the (still encrypted) traffic along. Off = direct connections only; joining may fail behind some routers.",
            settings.publicFallback) { v ->
            settings.publicFallback = v
            // Sessions were dialed with the old choice: drop them and dial again.
            // Retire, unbind, dial, bind, release — in that order ([AppModel.redial]).
            model.launchIO { model.redial() }
        }
    }
    SettingRow("Stay connected for notifications",
        "Skwod uses no Google push service. To notify you about new messages and calls it keeps a connection to your Skwod open, shown as a small silent notification.",
        settings.keepConnected) { v ->
        settings.keepConnected = v
        if (v && Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        ConnectionService.sync(ctx)
    }
    if (settings.keepConnected) {
        Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Battery optimization", color = Color.White)
                Text(if (exempt) "Skwod may stay connected while the phone sleeps."
                    else "Android pauses Skwod's connection when the phone sleeps, so messages and calls can arrive late.",
                    color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
            }
            if (!exempt) TextButton(onClick = { explainBattery = true }) { Text("Fix") }
        }
    }
    SettingRow("Hide message content",
        "Notifications say “New message” instead of showing who wrote what.",
        settings.hideMessageContent) { settings.hideMessageContent = it }
    SettingRow("Sound for new messages",
        "A short sound when a message arrives in a chat you're not looking at. Never under Do Not Disturb.",
        settings.soundReceived) { settings.soundReceived = it }
    SettingRow("Sound when a message is sent",
        "A soft sound once your message has been delivered to the skwod.",
        settings.soundSent) { settings.soundSent = it }
    SettingRow("Send typing indicators",
        "Others in a chat see when you're typing, and you see when they are. The host can see when you're typing in a chat, just as it sees when you send.",
        settings.typingIndicators) { settings.typingIndicators = it }
    SettingRow("Hide Skwod in recent apps",
        "The app switcher shows a blank card instead of your chats.",
        settings.recentsPrivacy) { v -> settings.recentsPrivacy = v; ScreenPrivacy.apply(ctx) }
    SettingRow("Block screenshots and screen recording",
        "Also blocks casting Skwod to another screen.",
        settings.screenSecurity) { v -> settings.screenSecurity = v; ScreenPrivacy.apply(ctx) }
    SettingRow("Play story music only when I tap",
        "A story's song is fetched for you by this Skwod's host, never straight from Apple — Apple doesn't see you, but the host sees which song you played and when. Off: it starts when you open the story. On: nothing is fetched until you tap the song.",
        settings.storyMusicTapToPlay) { v -> settings.storyMusicTapToPlay = v }

    if (explainBattery) {
        AlertDialog(
            onDismissRequest = { explainBattery = false },
            confirmButton = {
                TextButton(onClick = { explainBattery = false; settings.batteryAsked = true; ConnectionService.requestBatteryExemption(ctx) }) { Text("Continue") }
            },
            dismissButton = { TextButton(onClick = { explainBattery = false; settings.batteryAsked = true }) { Text("Not now") } },
            title = { Text("Let Skwod stay connected?") },
            text = {
                Text("Skwod doesn't use Google's push service, so nobody but your own Skwod knows when you get a message. The price is that the app has to keep its own connection open.\n\nWhen the phone sleeps, Android cuts that connection unless Skwod is exempt from battery optimization. Android will ask you to allow it next. Without it, notifications and calls can arrive late — you can change this any time in Android's settings.")
            }
        )
    }
}

/** One-time, polite prompt after sign-in: explain the background connection before asking. */
@Composable
fun BatteryPromptOnce() {
    val ctx = LocalContext.current
    val settings = AppSettings.get(ctx)
    var show by remember { mutableStateOf(settings.keepConnected && !settings.batteryAsked && !ConnectionService.isBatteryExempt(ctx)) }
    if (!show) return
    AlertDialog(
        onDismissRequest = { show = false; settings.batteryAsked = true },
        confirmButton = {
            TextButton(onClick = { show = false; settings.batteryAsked = true; ConnectionService.requestBatteryExemption(ctx) }) { Text("Continue") }
        },
        dismissButton = { TextButton(onClick = { show = false; settings.batteryAsked = true }) { Text("Not now") } },
        title = { Text("Notifications without Google") },
        text = {
            Text("Skwod never uses Google's push service. Instead it keeps a quiet connection to your Skwod open (you'll see a small “Skwod” notification) and notifies you itself.\n\nAndroid pauses that connection when the phone sleeps unless Skwod is exempt from battery optimization. Allow it on the next screen to get messages and calls on time. You can change this later under Profile → Privacy & notifications.")
        }
    )
}

/** In-app prompt while a call is ringing (the notification covers the backgrounded case). */
@Composable
fun IncomingCallDialog(call: IncomingCall, onAnswer: () -> Unit, onDecline: () -> Unit) {
    AlertDialog(
        onDismissRequest = {},
        confirmButton = {
            Button(onClick = onAnswer, colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF22C55E))) {
                Icon(Icons.Filled.Call, null); Spacer(Modifier.width(6.dp)); Text("Answer")
            }
        },
        dismissButton = {
            Button(onClick = onDecline, colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEF4444))) {
                Icon(Icons.Filled.CallEnd, null); Spacer(Modifier.width(6.dp)); Text("Decline")
            }
        },
        title = { Text("Incoming call") },
        text = { Text("${call.callerName} started an end-to-end encrypted call.") }
    )
}
