package io.skwod.app

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

private fun Context.findActivity(): Activity? {
    var c: Context? = this
    while (c != null && c !is Activity) c = (c as? ContextWrapper)?.baseContext
    return c as? Activity
}

/**
 * The lock screen. While it is up the activity composes this and nothing else — no chat, no
 * dialog, no sheet exists behind it to be seen in the app switcher or reached by a stray tap.
 * Authentication is tried once by itself when it appears; "Unlock" tries again.
 */
@Composable
fun LockScreen() {
    val ctx = LocalContext.current
    var failed by remember { mutableStateOf(false) }
    fun unlock() { ctx.findActivity()?.let { a -> AppLock.unlock(a) { ok -> failed = !ok } } }
    LaunchedEffect(Unit) { unlock() }
    Column(Modifier.fillMaxSize().padding(32.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Image(rememberAppLogo(), null, Modifier.size(88.dp))
        Spacer(Modifier.height(20.dp))
        Text("Skwod is locked", color = Color.White, style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(20.dp))
        Button(onClick = { unlock() }) { Text("Unlock") }
        if (failed && !AppLock.available(ctx)) {
            Spacer(Modifier.height(12.dp))
            Text("This phone has no screen lock any more. Set one in Android's settings to open Skwod.",
                color = Color(0xFFFB923C), style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** Privacy card, top: the app-lock switch and, when it is on, how long the app may be away. */
@Composable
fun AppLockSetting() {
    val ctx = LocalContext.current
    val settings = AppSettings.get(ctx)
    var message by remember { mutableStateOf("") }
    var picking by remember { mutableStateOf(false) }

    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text("App lock", color = Color.White)
            Text("Ask for ${AppLock.METHOD} or your device passcode to open Skwod.",
                color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
        }
        Switch(checked = settings.appLock, onCheckedChange = { want ->
            message = ""
            val activity = ctx.findActivity() ?: return@Switch
            if (!AppLock.available(ctx)) { message = "Set a screen lock on this phone first (Android settings → Security)."; return@Switch }
            // One successful authentication first, either way: nobody turns on a lock they
            // can't pass, and nobody but the owner turns it off.
            AppLock.authenticate(activity, if (want) "Turn on app lock" else "Turn off app lock") { ok ->
                if (ok) {
                    settings.appLock = want
                    // Turned off: a lock that closed while its own prompt was up opens with it.
                    if (!want) AppLock.set(false)
                } else message = "Not changed — that wasn't confirmed."
            }
        })
    }
    if (settings.appLock) {
        Row(Modifier.fillMaxWidth().clickable { picking = true }.padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("Lock after", color = Color.White, modifier = Modifier.weight(1f))
            Box {
                Text(AppLockPolicy.label(settings.appLockMinutes), color = SkAccent)
                DropdownMenu(expanded = picking, onDismissRequest = { picking = false }) {
                    AppLockPolicy.options.forEach { (minutes, label) ->
                        DropdownMenuItem(text = { Text(label) }, onClick = {
                            picking = false; message = ""
                            // A longer delay weakens the lock: only the owner may ([LockSettings]).
                            if (!LockSettings.needsAuthentication(settings.appLockMinutes, minutes)) settings.appLockMinutes = minutes
                            else ctx.findActivity()?.let { activity ->
                                AppLock.authenticate(activity, "Change app lock") { ok ->
                                    if (ok) settings.appLockMinutes = minutes else message = "Not changed — that wasn't confirmed."
                                }
                            }
                        })
                    }
                }
            }
        }
    }
    if (message.isNotEmpty()) Text(message, color = Color(0xFFFB923C), style = MaterialTheme.typography.labelSmall)
}
