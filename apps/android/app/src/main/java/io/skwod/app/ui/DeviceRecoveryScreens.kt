package io.skwod.app

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val Warn = Color(0xFFFB923C)
private val Good = Color(0xFF4ADE80)
private val Danger = Color(0xFFF87171)

/**
 * Build 44a's account screens — devices, the recovery key, restoring, the states an install can
 * be in — with the same structure, order and words as the Apple app's
 * `DeviceAndRecoveryViews.swift`. The decisions behind them are in `AccountSecurity.kt`.
 */

// ---- Devices ----

/** Profile → Encryption → Devices. */
@Composable
fun DevicesDialog(onClose: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var rows by remember { mutableStateOf<List<DeviceRows.Row>>(emptyList()) }
    var max by remember { mutableStateOf(0) }
    var erased by remember { mutableStateOf<List<uniffi.skwod_core.ErasedDevice>>(emptyList()) }
    var loaded by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var renaming by remember { mutableStateOf<DeviceRows.Row?>(null) }
    var removing by remember { mutableStateOf<DeviceRows.Row?>(null) }
    var markingLost by remember { mutableStateOf<uniffi.skwod_core.ErasedDevice?>(null) }
    // Devices a backup restore brought back that no other device has confirmed yet (audit M2).
    var unconfirmed by remember { mutableStateOf<List<String>>(emptyList()) }
    var addingByQr by remember { mutableStateOf(false) }
    var linking by remember { mutableStateOf(false) }
    val revision = model.account.revision.intValue
    val requests = model.linkRequests.intValue

    suspend fun load() {
        val list = withContext(Dispatchers.IO) { model.account.refreshDeviceNames() }
        if (list != null) {
            rows = DeviceRows.sorted(list.devices.map { DeviceRows.Row(it.deviceId, it.name, it.createdAt, it.lastActiveAt, it.isThisDevice, it.verified) })
            max = list.maxDevices.toInt()
            erased = try { withContext(Dispatchers.IO) { model.client?.erasedDevices() } ?: emptyList() } catch (_: Exception) { emptyList() }
            unconfirmed = try { withContext(Dispatchers.IO) { model.client?.unconfirmedRestoredDevices() } ?: emptyList() } catch (_: Exception) { emptyList() }
            message = ""
        } else if (!loaded) message = "Couldn't load your devices — check your connection."
        loaded = true
    }
    LaunchedEffect(model.current?.id, revision, requests) { load() }

    /** Run one change, then re-read the list; [then] only when it worked. */
    fun change(failure: String, then: () -> Unit = {}, call: suspend (uniffi.skwod_core.SkwodClient) -> Unit) {
        val c = model.client ?: run { message = "Not connected."; return }
        if (busy) return
        busy = true; message = ""
        scope.launch {
            val ok = try { withContext(Dispatchers.IO) { call(c) }; true } catch (e: Exception) {
                if (!model.routeIfDeviceError(e)) message = coreErrorDetail(e) ?: failure
                false
            }
            if (ok) { load(); then() }
            busy = false
        }
    }

    if (linking) { DeviceLinkApproveDialog { linking = false; scope.launch { load() } }; return }
    if (addingByQr) { AddDeviceDialog { addingByQr = false; scope.launch { load() } }; return }

    Dialog(onDismissRequest = onClose) {
        Surface(color = GlassDialogTone, shape = RoundedCornerShape(20.dp)) {
            Column(Modifier.padding(20.dp).verticalScroll(rememberScrollState())) {
                Text("Devices", color = Color.White, style = MaterialTheme.typography.titleLarge)
                if (max > 0) Text(DeviceRows.countLine(rows.size, max), color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.bodySmall)
                if (DeviceRows.atLimit(rows.size, max)) {
                    Spacer(Modifier.height(4.dp))
                    Text(DeviceRows.limitLine(max), color = Warn, style = MaterialTheme.typography.bodySmall)
                }
                Spacer(Modifier.height(10.dp))
                if (!loaded) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp, color = SkAccent)
                val now = System.currentTimeMillis()
                rows.forEach { row ->
                    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)
                        .background(Color.White.copy(alpha = 0.05f), RoundedCornerShape(12.dp))
                        .then(if (!row.verified) Modifier.border(1.dp, Warn.copy(alpha = 0.5f), RoundedCornerShape(12.dp)) else Modifier)
                        .padding(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Devices, null, tint = if (row.verified) Color.White.copy(alpha = 0.7f) else Warn, modifier = Modifier.size(20.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(DeviceLabel.shown(row.name), color = Color.White, fontWeight = FontWeight.SemiBold, maxLines = 1, modifier = Modifier.weight(1f, fill = false))
                            if (row.isThisDevice) {
                                Spacer(Modifier.width(8.dp))
                                Text("This device", color = Color.Black, fontSize = 11.sp,
                                    modifier = Modifier.background(SkAccent, RoundedCornerShape(50)).padding(horizontal = 8.dp, vertical = 2.dp))
                            }
                        }
                        Text(DeviceRows.secondLine(row, now), color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
                        if (row.deviceId in unconfirmed) {
                            // Restored from a backup that may be older than the account (audit
                            // M2): it gets nothing until the user, or a device they confirmed, says so.
                            Text("From your backup. Is this still your device? Until you say so, nothing is synced to it.", color = Warn, style = MaterialTheme.typography.labelSmall)
                            TextButton(enabled = !busy, onClick = {
                                change("Couldn't confirm that device — check your connection.") { c -> c.confirmRestoredDevice(row.deviceId) }
                            }) { Text("Yes, it's mine", color = Warn) }
                        } else if (!row.verified) Text(DeviceRows.UNVERIFIED, color = Warn, style = MaterialTheme.typography.labelSmall)
                        TextButton(enabled = !busy, onClick = { if (row.isThisDevice) renaming = row else removing = row }) {
                            Text(DeviceRows.action(row), color = if (row.isThisDevice) SkAccent else Danger)
                        }
                    }
                }
                if (erased.isNotEmpty()) {
                    Spacer(Modifier.height(12.dp))
                    Text("Erased devices", color = Color.White, style = MaterialTheme.typography.titleSmall)
                    erased.forEach { e ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                            Text("Erased ${AccountDates.day(e.erasedAt)}", color = Color.White.copy(alpha = 0.7f), modifier = Modifier.weight(1f))
                            TextButton(enabled = !busy, onClick = { markingLost = e }) { Text("It was lost or stolen…", color = Danger) }
                        }
                    }
                }
                if (message.isNotEmpty()) { Spacer(Modifier.height(6.dp)); Text(message, color = Warn, style = MaterialTheme.typography.labelSmall) }
                Spacer(Modifier.height(12.dp))
                // Build 48: the new device scans a QR shown here — nothing to type or paste.
                run {
                    Button(enabled = !busy && loaded && !DeviceRows.atLimit(rows.size, max), onClick = { addingByQr = true }, modifier = Modifier.fillMaxWidth()) {
                        Text("Add a device")
                    }
                }
                OutlinedButton(enabled = !busy && loaded && !DeviceRows.atLimit(rows.size, max), onClick = { linking = true }, modifier = Modifier.fillMaxWidth()) {
                    Text(if (requests > 0) "Link a device… (a device is waiting)" else "Link a device…")
                }
                TextButton(onClick = onClose, modifier = Modifier.align(Alignment.End)) { Text("Done") }
            }
        }
    }

    renaming?.let { row ->
        var name by remember(row.deviceId) { mutableStateOf(row.name ?: "") }
        AlertDialog(
            onDismissRequest = { renaming = null },
            confirmButton = {
                TextButton(enabled = DeviceLabel.cleaned(name).isNotEmpty(), onClick = {
                    val cleaned = DeviceLabel.cleaned(name); renaming = null
                    change("Couldn't rename this device — check your connection.") { c -> c.renameDevice(cleaned) }
                }) { Text("Save") }
            },
            dismissButton = { TextButton(onClick = { renaming = null }) { Text("Cancel") } },
            title = { Text("Rename") },
            text = {
                OutlinedTextField(name, { name = it.replace("\n", " ").take(DeviceLabel.MAX_LENGTH) }, singleLine = true,
                    label = { Text("Device name") }, modifier = Modifier.fillMaxWidth())
            }
        )
    }
    removing?.let { row ->
        AlertDialog(
            onDismissRequest = { removing = null },
            confirmButton = {
                TextButton(onClick = {
                    removing = null
                    // Removing a device retires the recovery key with it: the new-key flow comes next.
                    change("Couldn't remove that device — check your connection.",
                        then = { model.account.recoveryKeyPrompt = RecoveryKeyReason.DEVICE_REMOVED; model.launchIO { model.account.accountChanged() } }) { c ->
                        c.unregisterDevice(row.deviceId)
                    }
                }) { Text("Remove device", color = Danger) }
            },
            dismissButton = { TextButton(onClick = { removing = null }) { Text("Cancel") } },
            title = { Text("Remove ${DeviceLabel.shown(row.name)}?") },
            text = { Text("It is signed out and can no longer read new messages. Removing a device also retires your recovery key, so you'll make a new one next.") }
        )
    }
    markingLost?.let { e ->
        AlertDialog(
            onDismissRequest = { markingLost = null },
            confirmButton = {
                TextButton(onClick = {
                    markingLost = null
                    change("Couldn't mark it as lost — check your connection.",
                        then = { model.account.recoveryKeyPrompt = RecoveryKeyReason.DEVICE_REMOVED; model.launchIO { model.account.accountChanged() } }) { c ->
                        c.markErasedDeviceRemoved(e.identityKeyHex)
                    }
                }) { Text("Mark as lost", color = Danger) }
            },
            dismissButton = { TextButton(onClick = { markingLost = null }) { Text("Cancel") } },
            title = { Text("Mark it lost or stolen?") },
            text = { Text("That device can never be restored, and your recovery key is retired now. You'll make a new one next.") }
        )
    }
}

// ---- Recovery key ----

/**
 * One flow, three steps: save the key (shown once), type its last 6 characters back, done. Used
 * for the first-run prompt, Profile → Recovery key, after a device removal, the
 * `recovery_key_needed` notice and after "compromised" — [reason] decides the header line and
 * whether "Not now" is offered.
 */
@Composable
fun RecoveryKeyDialog(reason: RecoveryKeyReason, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val model = AppModel.get(ctx)
    val scope = rememberCoroutineScope()
    var step by remember { mutableStateOf(1) }
    // Generated once per flow and never stored by the app: closing the dialog forgets it.
    val key = remember { try { uniffi.skwod_core.generateRecoveryKey() } catch (_: Exception) { "" } }
    var typed by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var showQr by remember { mutableStateOf(false) }
    var ownPassphrase by remember { mutableStateOf(false) }
    var instantFrom by remember { mutableStateOf<Long?>(null) }

    if (ownPassphrase) { KeyBackupDialog(enabled = false) { ownPassphrase = false; onClose() }; return }

    fun close(snooze: Boolean) {
        if (snooze) model.launchIO { model.account.snoozeRecoveryKeyPrompt() }
        model.account.revision.intValue++
        onClose()
    }

    AlertDialog(
        // The key is shown once: a stray tap outside must not throw it away.
        onDismissRequest = {},
        confirmButton = {
            when (step) {
                1 -> TextButton(enabled = key.isNotEmpty(), onClick = { step = 2; message = "" }) { Text("I've saved it") }
                2 -> TextButton(enabled = !busy && typed.isNotBlank(), onClick = {
                    if (!RecoveryKeyCheck.matches(typed, key)) { message = "That doesn't match. Go back and check what you saved."; return@TextButton }
                    busy = true; message = ""
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) { model.client!!.enableKeyBackup(key) }
                            instantFrom = try { withContext(Dispatchers.IO) { model.client!!.recoveryKeyInstantFrom() } } catch (_: Exception) { null }
                            step = 3
                        } catch (e: Exception) {
                            if (!model.routeIfDeviceError(e)) message = coreErrorDetail(e) ?: "Couldn't turn on recovery — check your connection."
                        }
                        busy = false
                    }
                }) { Text(if (busy) "…" else "Turn on recovery") }
                else -> TextButton(onClick = { close(false) }) { Text("Done") }
            }
        },
        dismissButton = {
            when (step) {
                1 -> TextButton(onClick = { close(reason.offersNotNow) }) { Text(if (reason.offersNotNow) "Not now" else "Cancel") }
                2 -> TextButton(enabled = !busy, onClick = { step = 1; typed = ""; message = "" }) { Text("Back") }
                else -> {}
            }
        },
        title = { Text(when (step) { 1 -> "Save your recovery key"; 2 -> "Check your recovery key"; else -> "Recovery key saved" }) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                when (step) {
                    1 -> {
                        reason.header?.let { Text(it, color = Warn, style = MaterialTheme.typography.bodySmall); Spacer(Modifier.height(8.dp)) }
                        Text("Your recovery key brings your account back if you lose this device: your identity, your skwods and your direct messages. Skwod can't recover it for you — nobody can.",
                            style = MaterialTheme.typography.bodySmall)
                        Spacer(Modifier.height(12.dp))
                        SelectionContainer { Text(key, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, fontSize = 16.sp, color = Color.White) }
                        Spacer(Modifier.height(6.dp))
                        Row {
                            TextButton(onClick = { SecureClipboard.copy(ctx, key) }) { Text("Copy") }
                            TextButton(onClick = { showQr = !showQr }) { Text("Show QR") }
                            TextButton(onClick = {
                                // Handed to whatever the user picks (a password manager, a printer
                                // service, a note): it leaves the app only by their own choice.
                                val send = Intent(Intent.ACTION_SEND).setType("text/plain")
                                    .putExtra(Intent.EXTRA_SUBJECT, "Skwod recovery key").putExtra(Intent.EXTRA_TEXT, key)
                                runCatching { ctx.startActivity(Intent.createChooser(send, "Share / print")) }
                            }) { Text("Share / print") }
                        }
                        if (showQr && key.isNotEmpty()) { QrImage(key, sizeDp = 180); Spacer(Modifier.height(6.dp)) }
                        Text("Write it down or keep it in a password manager. It is shown only once.", color = Warn, style = MaterialTheme.typography.labelSmall)
                        TextButton(onClick = { ownPassphrase = true }) { Text("Use my own passphrase instead") }
                    }
                    2 -> {
                        Text("Type the last 6 characters of your recovery key.", style = MaterialTheme.typography.bodySmall)
                        Spacer(Modifier.height(10.dp))
                        OutlinedTextField(typed, { typed = it.take(16) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                            textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace))
                    }
                    else -> Text(RecoveryPrompt.savedBody(instantFrom, System.currentTimeMillis(), AccountDates::day), style = MaterialTheme.typography.bodySmall)
                }
                if (message.isNotEmpty()) { Spacer(Modifier.height(8.dp)); Text(message, color = Warn, style = MaterialTheme.typography.labelSmall) }
            }
        }
    )
}

/** The Profile row: "Not set" + save, or "On" + when it becomes instant + replace / compromised. */
@Composable
fun RecoveryKeyRow() {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var on by remember { mutableStateOf<Boolean?>(null) }
    var instantFrom by remember { mutableStateOf<Long?>(null) }
    var confirmCompromised by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    val revision = model.account.revision.intValue
    val showing = model.account.recoveryKeyPrompt

    LaunchedEffect(model.current?.id, revision, showing) {
        val c = model.client ?: return@LaunchedEffect
        on = try { withContext(Dispatchers.IO) { c.keyBackupEnabled() } } catch (_: Exception) { null }
        instantFrom = if (on == true) try { withContext(Dispatchers.IO) { c.recoveryKeyInstantFrom() } } catch (_: Exception) { null } else null
    }

    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Recovery key", color = Color.White, modifier = Modifier.weight(1f))
            when (on) {
                true -> Text("On", color = Good, fontWeight = FontWeight.SemiBold)
                false -> Text("Not set", color = Warn)
                null -> {}
            }
        }
        if (on == true) {
            Text(RecoveryPrompt.rowStatus(instantFrom, System.currentTimeMillis(), AccountDates::day), color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
            Row {
                TextButton(onClick = { model.account.recoveryKeyPrompt = RecoveryKeyReason.MANUAL }) { Text("Replace…") }
                TextButton(onClick = { confirmCompromised = true }) { Text("My recovery key is compromised…", color = Danger) }
            }
        } else if (on == false) {
            Text("Without one, losing every device means losing your messages.", color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
            TextButton(onClick = { model.account.recoveryKeyPrompt = RecoveryKeyReason.MANUAL }) { Text("Save a recovery key…") }
        }
        if (message.isNotEmpty()) Text(message, color = Warn, style = MaterialTheme.typography.labelSmall)
    }

    if (confirmCompromised) {
        AlertDialog(
            onDismissRequest = { confirmCompromised = false },
            confirmButton = {
                TextButton(onClick = {
                    confirmCompromised = false; message = ""
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) { model.client!!.reportRecoveryKeyCompromised() }
                            model.account.recoveryKeyPrompt = RecoveryKeyReason.COMPROMISED
                            model.launchIO { model.account.accountChanged() }
                        } catch (e: Exception) {
                            if (!model.routeIfDeviceError(e)) message = coreErrorDetail(e) ?: "Couldn't retire the key — check your connection."
                        }
                    }
                }) { Text("Retire it", color = Danger) }
            },
            dismissButton = { TextButton(onClick = { confirmCompromised = false }) { Text("Cancel") } },
            title = { Text("Retire your recovery key?") },
            text = { Text("It stops working at once, on every device, and can't be brought back. You'll make a new one next.") }
        )
    }
}

// ---- Setting up an install: link / restore / reset ----

@Composable
private fun ChoiceCard(icon: androidx.compose.ui.graphics.vector.ImageVector, title: String, caption: String, tint: Color = Color.White, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp).clip(RoundedCornerShape(12.dp))
        .background(Color.White.copy(alpha = 0.06f)).clickable(onClick = onClick).padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, null, tint = tint, modifier = Modifier.size(24.dp))
        Spacer(Modifier.width(12.dp))
        Column {
            Text(title, color = tint, fontWeight = FontWeight.SemiBold)
            Text(caption, color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.labelSmall)
        }
    }
}

/**
 * "Set up this device": this install has no identity and the account already has a device. A
 * password alone must never be enough to read someone's messages, so there are exactly three
 * ways in — and registering a fresh device silently is not one of them.
 */
@Composable
fun SetUpDeviceDialog() {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var choice by remember { mutableStateOf("") }
    var confirmReset by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }

    when (choice) {
        "link" -> { DeviceLinkDialog(onBack = { choice = "" }); return }
        "restore" -> { RestoreDialog(onClose = { choice = "" }); return }
    }

    AlertDialog(
        onDismissRequest = {},
        confirmButton = { TextButton(onClick = { model.needsDeviceLink = false }) { Text("Not now") } },
        title = { Text("Set up this device") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text("Your account already has a device. Choose how to bring this one in.", style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(10.dp))
                ChoiceCard(Icons.Filled.QrCode2, "Link from another device", "Scan or type a code on a device you're signed in on.") { choice = "link" }
                ChoiceCard(Icons.Filled.Key, "Restore with your recovery key", "Brings back your identity, skwods and direct messages.") { choice = "restore" }
                ChoiceCard(Icons.Filled.RestartAlt, "Reset encryption", "Removes your other devices. Use only if you have nothing else.", tint = Danger) { confirmReset = true }
                if (message.isNotEmpty()) Text(message, color = Warn, style = MaterialTheme.typography.labelSmall)
            }
        }
    )

    if (confirmReset) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            confirmButton = {
                TextButton(onClick = {
                    confirmReset = false; message = ""
                    // With a PIN on the account the core asks for it; without one the reset waits 7 days.
                    scope.launch { withContext(Dispatchers.IO) { model.account.resetDevices(null) }?.let { message = it } }
                }) { Text("Reset and sign out my other devices", color = Danger) }
            },
            dismissButton = { TextButton(onClick = { confirmReset = false }) { Text("Cancel") } },
            title = { Text("Reset encryption?") },
            text = { Text("This removes every other device from your account and gives this one new keys. Your contacts will see your safety number change, and anything only your old devices could read stays unreadable here.") }
        )
    }
}

/** Restore with the recovery key (or the passphrase a backup was made with). */
@Composable
fun RestoreDialog(onClose: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var key by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        confirmButton = {
            TextButton(enabled = !busy && key.isNotBlank(), onClick = {
                busy = true; message = ""
                scope.launch {
                    when (val outcome = withContext(Dispatchers.IO) { model.account.restore(key) }) {
                        // Restored, waiting or asking for the PIN: the next screen takes over.
                        AccountFlows.RestoreOutcome.Restored, AccountFlows.RestoreOutcome.Waiting, AccountFlows.RestoreOutcome.Pin -> { key = ""; onClose() }
                        AccountFlows.RestoreOutcome.NoBackup -> message = "No backup exists for this account."
                        AccountFlows.RestoreOutcome.WrongKey -> message = "That recovery key doesn't match."
                        is AccountFlows.RestoreOutcome.Failed -> message = outcome.why
                    }
                    busy = false
                }
            }) { Text(if (busy) "Restoring…" else "Restore") }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onClose) { Text("Cancel") } },
        title = { Text("Restore with your recovery key") },
        text = {
            Column {
                Text("Brings back your identity, skwods and direct messages.", style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(key, { key = it }, label = { Text("Recovery key or passphrase") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), modifier = Modifier.fillMaxWidth())
                if (message.isNotEmpty()) { Spacer(Modifier.height(6.dp)); Text(message, color = Warn, style = MaterialTheme.typography.labelSmall) }
            }
        }
    )
}

/**
 * "Waiting to restore": the restore is a recovery REQUEST — another device's approval, the
 * account PIN, or the 7-day hold completes it. Shown whenever the install is in that state.
 */
@Composable
fun RecoveryWaitingDialog(onClose: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var code by remember { mutableStateOf("") }
    var completesAt by remember { mutableStateOf<Long?>(null) }
    var contested by remember { mutableStateOf(false) }
    var pin by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var now by remember { mutableStateOf(System.currentTimeMillis()) }

    suspend fun readState() {
        val c = model.client ?: return
        code = try { withContext(Dispatchers.IO) { c.recoveryFingerprint() } } catch (_: Exception) { code }
        completesAt = try { withContext(Dispatchers.IO) { c.recoveryCompletesAt() } } catch (_: Exception) { completesAt }
        contested = try { withContext(Dispatchers.IO) { c.recoveryContested() } } catch (_: Exception) { contested }
        now = System.currentTimeMillis()
    }

    suspend fun retry(withPin: String?, quiet: Boolean) {
        if (busy) return
        busy = true
        if (!quiet) message = ""
        when (val outcome = withContext(Dispatchers.IO) { model.account.retryRestore(withPin) }) {
            AccountFlows.RestoreOutcome.Waiting -> { if (!quiet) message = "Still waiting." }
            // Done, or the PIN screen came up (a wrong PIN says how many tries are left there).
            AccountFlows.RestoreOutcome.Restored, AccountFlows.RestoreOutcome.Pin -> {}
            is AccountFlows.RestoreOutcome.Failed -> if (!quiet) message = outcome.why
            else -> {}
        }
        readState()
        busy = false
    }

    // The code first; then ask once at once (the server says when the hold ends, or that the
    // request is contested — not remembered across launches), and every 15 s while on screen.
    LaunchedEffect(Unit) {
        readState()
        retry(null, quiet = true)
        while (true) { delay(15_000); retry(null, quiet = true) }
    }

    AlertDialog(
        onDismissRequest = {},
        confirmButton = { TextButton(enabled = !busy, onClick = { scope.launch { retry(null, quiet = false) } }) { Text("Check again") } },
        dismissButton = { TextButton(onClick = onClose) { Text("Close") } },
        title = { Text("Waiting to restore") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally) {
                Text("This restore needs one more check. Approve it on another of your devices — it will show this code:", style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(12.dp))
                Text(code.ifEmpty { "…" }, fontFamily = FontFamily.Monospace, fontSize = 28.sp, fontWeight = FontWeight.Bold, color = Color.White)
                Spacer(Modifier.height(12.dp))
                // Omitted until the server has said when the hold ends; a contested request
                // waits for an approval instead.
                RestoreWaitLine.text(completesAt, contested, now)?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(pin, { v -> pin = v.filter { it.isDigit() }.take(20) }, label = { Text("Account PIN (optional)") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    modifier = Modifier.fillMaxWidth())
                Button(enabled = !busy && pin.length >= 4, onClick = { val p = pin; pin = ""; scope.launch { retry(p, quiet = false) } },
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Use PIN") }
                if (message.isNotEmpty()) { Spacer(Modifier.height(6.dp)); Text(message, color = Warn, style = MaterialTheme.typography.labelSmall) }
            }
        }
    )
}

/**
 * In place of the app when this install is no longer a device of the account: removed by
 * another device, or stopped because the account was restored somewhere else.
 */
@Composable
fun DeviceStoppedScreen(screen: InstallRoute.Screen, onSignedOut: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    val removed = screen == InstallRoute.Screen.REMOVED
    Column(Modifier.fillMaxSize().padding(32.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(if (removed) Icons.Filled.PhonelinkErase else Icons.Filled.SyncProblem, null, tint = Warn, modifier = Modifier.size(56.dp))
        Spacer(Modifier.height(18.dp))
        Text(if (removed) "This device was removed" else "Your account was restored on another device",
            color = Color.White, style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
        Spacer(Modifier.height(10.dp))
        Text(if (removed) "Another of your devices removed this one from your account. Nothing here can be read by it any more."
             else "This copy has stopped. If that wasn't you, restore here with your recovery key and change your password.",
            color = Color.White.copy(alpha = 0.7f), style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
        Spacer(Modifier.height(24.dp))
        Button(enabled = !busy, onClick = {
            busy = true
            scope.launch { withContext(Dispatchers.IO) { model.account.setUpAgain() }; busy = false }
        }, modifier = Modifier.fillMaxWidth()) { Text("Set up this device again") }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(enabled = !busy, onClick = {
            busy = true
            scope.launch {
                val another = withContext(Dispatchers.IO) { model.leaveCurrent() }
                busy = false
                if (!another) onSignedOut()
            }
        }, modifier = Modifier.fillMaxWidth()) { Text("Sign out") }
    }
}

/**
 * Another device is restoring this account WITHOUT a usable recovery key and asks this one.
 * Never answered by the app: the user compares the code and decides. The answer names the
 * request by the id its notice carried, so it cannot land on a request that replaced it.
 */
@Composable
fun RecoveryRequestDialog(request: RecoveryRequest) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var busy by remember(request.requestId) { mutableStateOf(false) }

    fun answer(approve: Boolean) {
        if (busy) return
        busy = true
        scope.launch {
            val (_, line) = withContext(Dispatchers.IO) { model.account.answer(request, approve) }
            // Approved / Blocked / "replaced by a newer one — nothing was approved" / why it failed.
            model.account.recoveryOutcome = line
            busy = false
        }
    }

    AlertDialog(
        onDismissRequest = {},
        confirmButton = { TextButton(enabled = !busy, onClick = { answer(true) }) { Text("Approve") } },
        dismissButton = {
            Row {
                // "Decide later": it stays in Profile → Encryption until it is answered or replaced.
                TextButton(enabled = !busy, onClick = { model.account.recoveryRequests.removeAll { it.requestId == request.requestId }; model.account.deferred.add(request) }) { Text("Decide later") }
                TextButton(enabled = !busy, onClick = { answer(false) }) { Text("Block", color = Danger) }
            }
        },
        title = { Text("Restore your account on another device?") },
        text = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("Someone signed in to your account is restoring it on a new device without your recovery key. Only approve if that is you, right now, and the new device shows this code:",
                    style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(12.dp))
                Text(request.fingerprint.ifEmpty { "—" }, fontFamily = FontFamily.Monospace, fontSize = 28.sp, fontWeight = FontWeight.Bold, color = Color.White)
            }
        }
    )
}

// ---- PIN ----

/** "Enter your account PIN" — for a reset, or to complete a waiting restore. */
@Composable
fun AccountPinPromptDialog(prompt: PinPrompt) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var confirmForgot by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = {},
        confirmButton = {
            TextButton(enabled = !busy && !prompt.locked && pin.length >= 4, onClick = {
                val p = pin; pin = ""; busy = true; message = ""
                scope.launch {
                    when (prompt.purpose) {
                        PinPrompt.Purpose.RESET -> withContext(Dispatchers.IO) { model.account.resetDevices(p) }?.let { message = it }
                        PinPrompt.Purpose.RESTORE -> when (val outcome = withContext(Dispatchers.IO) { model.account.retryRestore(p) }) {
                            is AccountFlows.RestoreOutcome.Failed -> message = outcome.why
                            AccountFlows.RestoreOutcome.Waiting -> { model.account.pinPrompt = null }
                            else -> {}
                        }
                    }
                    busy = false
                }
            }) { Text(if (busy) "…" else "Continue") }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = { model.account.pinPrompt = null }) { Text("Cancel") } },
        title = { Text("Enter your account PIN") },
        text = {
            Column {
                Text("This account is protected by a PIN.", style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(pin, { v -> pin = v.filter { it.isDigit() }.take(20) }, label = { Text("Account PIN") }, singleLine = true,
                    enabled = !prompt.locked, visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword), modifier = Modifier.fillMaxWidth())
                prompt.message?.let { Spacer(Modifier.height(6.dp)); Text(it, color = Warn, style = MaterialTheme.typography.labelSmall) }
                if (message.isNotEmpty()) { Spacer(Modifier.height(6.dp)); Text(message, color = Warn, style = MaterialTheme.typography.labelSmall) }
                // Without the PIN a reset is still possible — after the wait every reset without one has.
                if (prompt.purpose == PinPrompt.Purpose.RESET) TextButton(enabled = !busy, onClick = { confirmForgot = true }) { Text("Forgot PIN?") }
            }
        }
    )

    if (confirmForgot) {
        AlertDialog(
            onDismissRequest = { confirmForgot = false },
            confirmButton = {
                TextButton(onClick = {
                    confirmForgot = false; busy = true; message = ""
                    scope.launch { withContext(Dispatchers.IO) { model.account.resetForgotPin() }?.let { message = it }; busy = false }
                }) { Text("Start the 7-day wait") }
            },
            dismissButton = { TextButton(onClick = { confirmForgot = false }) { Text("Cancel") } },
            title = { Text("Reset without the PIN?") },
            text = { Text("The reset waits 7 days so your other devices can stop it. There is no shortcut.") }
        )
    }
}

// ---- Erase ----

/** "Erase this device…" — the explicit wipe, separate from signing out. */
@Composable
fun EraseDeviceDialog(onClose: () -> Unit, onErased: (anotherSkwod: Boolean) -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var check by remember { mutableStateOf<uniffi.skwod_core.EraseCheck?>(null) }
    var confirmedUnsafe by remember { mutableStateOf(false) }
    var askUnsafe by remember { mutableStateOf(false) }
    var asLost by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var offerOffline by remember { mutableStateOf(false) }
    var linking by remember { mutableStateOf(false) }
    val revision = model.account.revision.intValue
    val keyFlow = model.account.recoveryKeyPrompt

    // Asked on open, and again when a recovery key was saved or a device linked from here.
    LaunchedEffect(revision, keyFlow, linking) {
        check = try { withContext(Dispatchers.IO) { model.client?.eraseCheck() } } catch (_: Exception) { null }
    }

    fun erase(evenIfOffline: Boolean) {
        if (busy) return
        busy = true; message = ""
        scope.launch {
            try {
                val another = withContext(Dispatchers.IO) { model.eraseThisDevice(asLost, evenIfOffline) }
                onErased(another)
            } catch (e: Exception) {
                // The server could not be reached: the device can still be erased here, and the
                // account's other devices will see it gone when it next would have answered.
                offerOffline = EraseCopy.offersOffline(coreErrorKind(e))
                message = coreErrorDetail(e) ?: e.message?.takeIf { e is IllegalStateException } ?: "Couldn't reach your Skwod."
            }
            busy = false
        }
    }

    if (linking) { DeviceLinkApproveDialog { linking = false }; return }

    val safe = check?.safe
    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        confirmButton = {
            if (safe != null && EraseCopy.eraseOffered(safe, confirmedUnsafe)) {
                TextButton(enabled = !busy, onClick = { erase(false) }) { Text(if (busy) "Erasing…" else "Erase this device", color = Danger) }
            }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onClose) { Text("Cancel") } },
        title = { Text(EraseCopy.TITLE) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(EraseCopy.BODY, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(10.dp))
                if (safe == null) Text("Checking what this account has to come back with…", color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.labelSmall)
                if (safe == false && !confirmedUnsafe) {
                    Column(Modifier.fillMaxWidth().background(Warn.copy(alpha = 0.10f), RoundedCornerShape(12.dp))
                        .border(1.dp, Warn.copy(alpha = 0.4f), RoundedCornerShape(12.dp)).padding(12.dp)) {
                        Text(EraseCopy.UNSAFE, color = Color.White.copy(alpha = 0.9f), style = MaterialTheme.typography.bodySmall)
                        Spacer(Modifier.height(6.dp))
                        Button(onClick = { model.account.recoveryKeyPrompt = RecoveryKeyReason.MANUAL }, modifier = Modifier.fillMaxWidth()) { Text("Save a recovery key") }
                        OutlinedButton(onClick = { linking = true }, modifier = Modifier.fillMaxWidth()) { Text("Link another device") }
                        TextButton(onClick = { askUnsafe = true }) { Text("Erase anyway…", color = Danger, style = MaterialTheme.typography.labelSmall) }
                    }
                    Spacer(Modifier.height(10.dp))
                }
                Row(Modifier.fillMaxWidth().clickable(enabled = !busy) { asLost = !asLost }, verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(asLost, onCheckedChange = { asLost = it }, enabled = !busy)
                    Text(EraseCopy.LOST_TOGGLE)
                }
                Text(EraseCopy.LOST_CAPTION, color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
                if (message.isNotEmpty()) { Spacer(Modifier.height(8.dp)); Text(message, color = Warn, style = MaterialTheme.typography.labelSmall) }
                if (offerOffline) TextButton(enabled = !busy, onClick = { erase(true) }) { Text("Erase anyway (offline)", color = Danger) }
            }
        }
    )

    if (askUnsafe) {
        AlertDialog(
            onDismissRequest = { askUnsafe = false },
            confirmButton = { TextButton(onClick = { askUnsafe = false; confirmedUnsafe = true }) { Text("Erase anyway", color = Danger) } },
            dismissButton = { TextButton(onClick = { askUnsafe = false }) { Text("Cancel") } },
            title = { Text("Erase without a way back?") },
            text = { Text("Your message history will be gone for good, and getting back into your account will take a 7-day reset.") }
        )
    }
}

// ---- Security activity ----

/** Profile → Encryption → Security activity: every security notice this device has shown, newest first. */
@Composable
fun SecurityActivityDialog(onClose: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    LaunchedEffect(Unit) { withContext(Dispatchers.IO) { model.account.loadActivity() } }
    val events = model.account.activity
    val now = System.currentTimeMillis()
    AlertDialog(
        onDismissRequest = onClose,
        confirmButton = { TextButton(onClick = onClose) { Text("Done") } },
        title = { Text("Security activity") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                if (events.isEmpty()) Text("Nothing yet. Changes to your devices, your recovery key and your contacts' devices are listed here.",
                    color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.bodySmall)
                events.forEach { e ->
                    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                        Text(e.title, color = Color.White, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyMedium)
                        Text(e.message, color = Color.White.copy(alpha = 0.7f), style = MaterialTheme.typography.bodySmall)
                        Text(AccountDates.ago(e.atMs, now), color = Color.White.copy(alpha = 0.4f), style = MaterialTheme.typography.labelSmall)
                    }
                    HorizontalDivider(color = Color.White.copy(alpha = 0.06f))
                }
            }
        }
    )
}

// ---- Everything about the account that can come up over any screen ----

/**
 * Root-level account prompts, one at a time, most pressing first. Composed by the activity next
 * to the app (never while the app lock is closed).
 */
@Composable
fun AccountPrompts() {
    val model = AppModel.get(LocalContext.current)
    val account = model.account
    LaunchedEffect(model.recoveryWaiting) { if (!model.recoveryWaiting) account.waitingClosed = false }
    val ctx = LocalContext.current
    // "Your account is back." — one line, then gone.
    LaunchedEffect(account.restoredLine) {
        account.restoredLine?.let { android.widget.Toast.makeText(ctx, it, android.widget.Toast.LENGTH_LONG).show(); account.restoredLine = null }
    }

    val pin = account.pinPrompt
    val request = account.recoveryRequests.firstOrNull()
    val keyReason = account.recoveryKeyPrompt
    when {
        pin != null -> AccountPinPromptDialog(pin)
        model.resetPending != null -> ResetPendingDialog()
        model.recoveryWaiting && !account.waitingClosed -> RecoveryWaitingDialog(onClose = { account.waitingClosed = true })
        model.needsDeviceLink -> SetUpDeviceDialog()
        account.recoveryOutcome != null -> AlertDialog(
            onDismissRequest = { account.recoveryOutcome = null },
            confirmButton = { TextButton(onClick = { account.recoveryOutcome = null }) { Text("OK") } },
            text = { Text(account.recoveryOutcome ?: "") })
        request != null -> RecoveryRequestDialog(request)
        keyReason != null -> RecoveryKeyDialog(keyReason) { account.recoveryKeyPrompt = null }
    }
}
