package io.skwod.app

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val Warn = Color(0xFFFB923C)
private val Good = Color(0xFF4ADE80)
private val Danger = Color(0xFFF87171)

/**
 * Profile → Encryption, in the order every platform uses: who and where this device is, Devices,
 * the recovery key, the account PIN, Security activity. ("Link a device…" lives inside Devices.)
 */
@Composable
fun EncryptionSection() {
    val model = AppModel.get(LocalContext.current)
    var showDevices by remember { mutableStateOf(false) }
    var showAddress by remember { mutableStateOf(false) }
    var showPin by remember { mutableStateOf(false) }
    var showActivity by remember { mutableStateOf(false) }
    var devices by remember { mutableStateOf<Pair<Int, Int>?>(null) }
    val requests = model.linkRequests.intValue
    val revision = model.account.revision.intValue

    LaunchedEffect(model.current?.id, requests, revision, showDevices) {
        val list = withContext(Dispatchers.IO) { model.account.refreshDeviceNames() } ?: return@LaunchedEffect
        devices = list.devices.size to list.maxDevices.toInt()
    }

    Text("Encryption", color = Color.White, style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(8.dp))
    InfoRow("User ID", model.current?.userId?.take(8)?.plus("…") ?: "—")
    InfoRow("Device", model.deviceId?.take(8)?.plus("…") ?: "Not set up")
    InfoRow("Protocol", "Signal (PQXDH, Double Ratchet)")
    InfoRow("Server", model.current?.let { w -> w.nodeId?.let { "Host key ${InviteLink.shortKey(it)}" } ?: w.server } ?: "—")
    Spacer(Modifier.height(6.dp))
    OutlinedButton(onClick = { showDevices = true }, modifier = Modifier.fillMaxWidth()) {
        Text("Devices" + (devices?.let { "  ·  ${DeviceRows.count(it.first, it.second)}" } ?: "") + if (requests > 0) "  ·  a device is waiting" else "")
    }
    // A restore of this install that is still waiting, or a restore elsewhere the user put off.
    if (model.recoveryWaiting) {
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { model.account.waitingClosed = false }, modifier = Modifier.fillMaxWidth()) { Text("Waiting to restore…", color = Warn) }
    }
    model.account.deferred.firstOrNull()?.let { request ->
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { model.account.deferred.remove(request); model.account.recoveryRequests.add(request) }, modifier = Modifier.fillMaxWidth()) {
            Text("A restore is waiting for your answer…", color = Warn)
        }
    }
    RecoveryKeyRow()
    OutlinedButton(onClick = { showPin = true }, modifier = Modifier.fillMaxWidth()) { Text("Account PIN…") }
    Spacer(Modifier.height(8.dp))
    OutlinedButton(onClick = { showActivity = true }, modifier = Modifier.fillMaxWidth()) { Text("Security activity") }
    Spacer(Modifier.height(8.dp))
    OutlinedButton(onClick = { showAddress = true }, modifier = Modifier.fillMaxWidth()) { Text("Show this Skwod's address (QR)") }

    if (showDevices) DevicesDialog { showDevices = false }
    if (showAddress) SkwodAddressDialog { showAddress = false }
    if (showPin) AccountPinDialog { showPin = false }
    if (showActivity) SecurityActivityDialog { showActivity = false }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(label, color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.bodySmall, modifier = Modifier.width(84.dp))
        Text(value, color = Color.White, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, maxLines = 1)
    }
}

/**
 * The skwod's address (host key, or https address) as a QR — no join code, no credentials — so a
 * new device of the same person lands on the right log-in screen before it is linked.
 */
@Composable
fun SkwodAddressDialog(onClose: () -> Unit) {
    val ctx = LocalContext.current
    val model = AppModel.get(ctx)
    val address = model.current?.address?.stored ?: ""
    AlertDialog(
        onDismissRequest = onClose,
        confirmButton = { TextButton(onClick = onClose) { Text("Done") } },
        dismissButton = { TextButton(onClick = { SecureClipboard.copy(ctx, address) }) { Text("Copy") } },
        title = { Text("This Skwod's address") },
        text = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("On your new device choose Log in and scan this. It only says where the Skwod is — the new device still needs your password, and then has to be linked.",
                    style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(14.dp))
                if (address.isNotEmpty()) QrImage(address, sizeDp = 200)
                model.current?.nodeId?.let {
                    Spacer(Modifier.height(8.dp))
                    Text("Host key ${InviteLink.shortKey(it)}", fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = Color.White.copy(alpha = 0.6f))
                }
            }
        }
    )
}

/** Account PIN (registration lock): set, change or remove. Needs this device's signature. */
@Composable
fun AccountPinDialog(onClose: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var current by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var ok by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }

    fun submit(newPin: String?) {
        if (busy) return
        busy = true; message = ""
        scope.launch {
            try {
                withContext(Dispatchers.IO) { model.client!!.setRegistrationPin(newPin, current.ifEmpty { null }) }
                ok = true
                message = if (newPin == null) "PIN removed." else "PIN saved. It can speed up a reset once it has been in place for 7 days."
            } catch (e: Exception) { ok = false; message = linkError(e) }
            busy = false
        }
    }

    AlertDialog(
        onDismissRequest = onClose,
        confirmButton = {
            TextButton(enabled = !busy && pin.length >= 4 && pin == confirm, onClick = { submit(pin) }) { Text("Save PIN") }
        },
        dismissButton = { TextButton(onClick = onClose) { Text(if (ok) "Done" else "Cancel") } },
        title = { Text("Account PIN") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text("If you ever lose every device, the PIN lets you reset your account's encryption straight away. Without one, a reset waits 7 days so your devices can stop it. A new PIN starts counting after 7 days in place. It protects no messages by itself — it only guards the reset.",
                    style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(10.dp))
                PinField(current, { current = it }, "Current PIN (if you set one)")
                Spacer(Modifier.height(8.dp))
                PinField(pin, { pin = it }, "New PIN (4+ digits)")
                Spacer(Modifier.height(8.dp))
                PinField(confirm, { confirm = it }, "Repeat the new PIN")
                if (pin.isNotEmpty() && confirm.isNotEmpty() && pin != confirm) {
                    Text("The two PINs don't match.", color = Warn, style = MaterialTheme.typography.labelSmall)
                }
                if (message.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text(message, color = if (ok) Good else Warn, style = MaterialTheme.typography.labelSmall)
                }
                TextButton(enabled = !busy, onClick = { submit(null) }) { Text("Remove the PIN", color = Danger) }
            }
        }
    )
}

@Composable
private fun PinField(value: String, onChange: (String) -> Unit, label: String) {
    OutlinedTextField(value, { v -> onChange(v.filter { it.isDigit() }.take(20)) }, label = { Text(label) }, singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        modifier = Modifier.fillMaxWidth())
}

/**
 * "Reset is waiting": an account reset without a (seasoned) PIN is held for 7 days, during which
 * any device still on the account cancels it. Offers the PIN, a re-check, or linking instead.
 */
@Composable
fun ResetPendingDialog() {
    val model = AppModel.get(LocalContext.current)
    val detail = model.resetPending ?: return
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }

    fun retry(usePin: Boolean) {
        if (busy) return
        busy = true; message = ""
        scope.launch {
            // The same call that started the wait finishes it: a reset begun with "Forgot PIN?"
            // must not be retried as a plain reset (which would only ask for the PIN again).
            val failed = withContext(Dispatchers.IO) {
                if (!usePin && model.account.resetIsForgotPin) model.account.resetForgotPin() else model.account.resetDevices(if (usePin) pin else null)
            }
            if (failed != null) message = failed
            else if (model.resetPending != null) message = if (usePin) "That PIN didn't finish the reset. It may be wrong, or newer than 7 days." else "Still waiting. ${model.resetPending}"
            busy = false
        }
    }

    AlertDialog(
        onDismissRequest = {},
        confirmButton = { TextButton(enabled = !busy, onClick = { retry(false) }) { Text("Check again") } },
        dismissButton = { TextButton(onClick = { model.resetPending = null }) { Text("Close") } },
        title = { Text("Reset is waiting") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(detail, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(8.dp))
                Text("Why the wait: a password alone must not be enough to take over an account. For 7 days, any device still signed in to this account stops the reset and warns its owner. If that's you on another device, link this one instead.",
                    style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(10.dp))
                Text("Have an account PIN? It finishes the reset now (if the PIN is at least 7 days old).",
                    style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(6.dp))
                PinField(pin, { pin = it }, "Account PIN")
                Button(enabled = !busy && pin.length >= 4, onClick = { retry(true) }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                    Text("Reset now with PIN")
                }
                TextButton(onClick = { model.resetPending = null; model.needsDeviceLink = true }) { Text("Link from another device instead") }
                if (message.isNotEmpty()) Text(message, color = Warn, style = MaterialTheme.typography.labelSmall)
            }
        }
    )
}

/**
 * Key backup (opt-in). The identity key and space keys are sealed under a generated 160-bit
 * recovery key or a strong passphrase and stored on the skwod's server as ciphertext. A
 * self-hosted server can attack it offline, so weak passphrases are refused by the core.
 */
@Composable
fun KeyBackupDialog(enabled: Boolean, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val model = AppModel.get(ctx)
    val scope = rememberCoroutineScope()
    var passphrase by remember { mutableStateOf("") }
    var generated by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var ok by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var remote by remember { mutableStateOf(false) }
    val problem = remember(passphrase) {
        if (passphrase.isEmpty()) null else try { uniffi.skwod_core.backupPassphraseProblem(passphrase) } catch (_: Exception) { null }
    }

    LaunchedEffect(Unit) {
        remote = try { withContext(Dispatchers.IO) { model.client?.hasRemoteKeyBackup() } ?: false } catch (_: Exception) { false }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        confirmButton = {
            TextButton(enabled = !busy && !ok && passphrase.isNotEmpty() && problem == null, onClick = {
                busy = true; message = ""
                scope.launch {
                    try {
                        withContext(Dispatchers.IO) { model.client!!.enableKeyBackup(passphrase) }
                        ok = true; message = "Key backup is on."
                    } catch (e: Exception) { message = linkError(e) }
                    busy = false
                }
            }) { Text("Turn on backup") }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onClose) { Text(if (ok) "Done" else "Cancel") } },
        title = { Text(if (enabled) "Key backup" else "Set up key backup") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text("Optional. Your identity key and space keys are sealed under this passphrase and stored on your Skwod's server as ciphertext. If you sign out or lose every device, it brings them back. The server can try guesses against it, so use the generated recovery key or a long passphrase.",
                    style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(10.dp))
                OutlinedButton(enabled = !busy && !ok, onClick = {
                    passphrase = try { uniffi.skwod_core.generateRecoveryKey() } catch (_: Exception) { "" }
                    generated = passphrase.isNotEmpty()
                }, modifier = Modifier.fillMaxWidth()) { Text("Generate a recovery key") }
                Spacer(Modifier.height(8.dp))
                if (generated) {
                    Text(passphrase, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, fontSize = 15.sp, color = Color.White)
                    Text("Write this down or save it in a password manager. It is shown only once.",
                        style = MaterialTheme.typography.labelSmall, color = Warn)
                    TextButton(onClick = { SecureClipboard.copy(ctx, passphrase) }) { Text("Copy (clears after 60 s)") }
                } else {
                    OutlinedTextField(passphrase, { passphrase = it }, label = { Text("Passphrase (14+ characters)") }, singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        modifier = Modifier.fillMaxWidth())
                    problem?.let { Text(it, color = Warn, style = MaterialTheme.typography.labelSmall) }
                }
                Spacer(Modifier.height(8.dp))
                Text("Anyone who can guess this passphrase — including whoever runs the server — can decrypt your keys. There is no reset: a forgotten passphrase means a lost backup.",
                    style = MaterialTheme.typography.labelSmall, color = Color.White.copy(alpha = 0.6f))
                if (remote || enabled) {
                    Spacer(Modifier.height(6.dp))
                    Text("This account already has a backup. Turning backup on here replaces it — the old passphrase (and any keys only that backup held) stops working.",
                        style = MaterialTheme.typography.labelSmall, color = Warn)
                    TextButton(enabled = !busy, onClick = {
                        busy = true; message = ""
                        scope.launch {
                            try {
                                withContext(Dispatchers.IO) { model.client!!.disableKeyBackup() }
                                ok = true; remote = false; message = "Key backup is off. The server copy was deleted."
                            } catch (e: Exception) { message = linkError(e) }
                            busy = false
                        }
                    }) { Text("Turn off and delete the backup", color = Danger) }
                }
                if (message.isNotEmpty()) Text(message, color = if (ok) Good else Warn, style = MaterialTheme.typography.labelSmall)
            }
        }
    )
}
