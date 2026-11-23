package io.skwod.app

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal fun linkError(e: Exception): String = when (e) {
    is uniffi.skwod_core.CoreException.ResetPending -> e.detail
    is uniffi.skwod_core.CoreException.LinkRequired -> e.detail
    is uniffi.skwod_core.CoreException.UpdateRequired -> "Update required: this Skwod and this app use different encryption versions. Update the app (or ask your host to update the server)."
    is uniffi.skwod_core.CoreException.IdentityChanged -> e.detail
    is uniffi.skwod_core.CoreException.Engine -> e.detail
    is uniffi.skwod_core.CoreException.Invalid -> e.detail
    else -> coreErrorDetail(e) ?: "Something went wrong — check your connection."
}

/**
 * Shown on a device that signed in to an account which already has a device. A password (or a
 * stolen session) must not be enough to read someone's messages, so a new device has to be
 * **linked**: it shows a one-time 80-bit code — as a QR and as text — the user scans or types it
 * on a device already on the account, and that device signs this one's identity key. The server
 * only relays public values. (The code originates on the NEW device, so the QR is shown here.)
 */
@Composable
fun DeviceLinkDialog(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val model = AppModel.get(ctx)
    var code by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf("") }
    var attempt by remember { mutableStateOf(0) }

    LaunchedEffect(attempt) {
        val c = model.client ?: run { error = "Not connected."; return@LaunchedEffect }
        error = ""
        try {
            code = withContext(Dispatchers.IO) { c.beginDeviceLink() }
            while (true) {
                val deviceId = withContext(Dispatchers.IO) { c.completeDeviceLink() }
                if (deviceId != null) {
                    model.deviceLinked(deviceId)
                    return@LaunchedEffect
                }
                delay(2000)
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            code = null
            // Not the device (yet / any more): that state has its own screen.
            if (!model.routeIfDeviceError(e)) error = linkError(e)
        }
    }

    AlertDialog(
        onDismissRequest = {},
        confirmButton = { TextButton(onClick = onBack) { Text("Back") } },
        title = { Text("Link from another device") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally) {
                Text("Open Skwod on a device you're signed in on, go to Profile → Encryption → Devices → “Link a device…”, and scan this — or type the code:",
                    style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
                Spacer(Modifier.height(14.dp))
                when {
                    code != null -> {
                        QrImage(Qr.LINK_PREFIX + code!!, sizeDp = 180)
                        Spacer(Modifier.height(10.dp))
                        Text(code!!, fontFamily = FontFamily.Monospace, fontSize = 20.sp, fontWeight = FontWeight.SemiBold)
                        Spacer(Modifier.height(10.dp))
                        Text("Waiting for the other device…", style = MaterialTheme.typography.labelSmall)
                    }
                    error.isNotEmpty() -> {
                        Text(error, color = Color(0xFFFB923C), style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center)
                        TextButton(onClick = { attempt++ }) { Text("Try again") }
                    }
                    else -> CircularProgressIndicator()
                }
                Spacer(Modifier.height(12.dp))
                Text("The code only works once and never leaves your two devices.",
                    style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center)
            }
        }
    )
}

/**
 * On a device already on the account: scan (or type) the code a new device is showing to link it.
 */
@Composable
fun DeviceLinkApproveDialog(onClose: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    var code by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var done by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var scanning by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun approve(value: String) {
        if (busy) return
        busy = true
        scope.launch {
            try {
                val ok = withContext(Dispatchers.IO) { model.client!!.approveDeviceLink(value) }
                done = ok
                message = if (ok) "Linked. The new device will finish setting up in a moment."
                else "No device is waiting with that code. Check the code on the new device — it expires after 10 minutes."
            } catch (e: Exception) { message = linkError(e) }
            busy = false
        }
    }

    if (scanning) {
        QrScannerDialog(
            title = "Scan the new device's code",
            hint = "Point the camera at the QR code shown on the device you are adding.",
            onResult = { raw ->
                scanning = false
                val scanned = Qr.linkCode(raw)
                if (scanned == null) message = "That isn't a Skwod device-link code."
                else { code = scanned; approve(scanned) }
            },
            onClose = { scanning = false })
        return
    }

    AlertDialog(
        onDismissRequest = onClose,
        confirmButton = {
            TextButton(enabled = !busy && (done || code.count { it.isLetterOrDigit() } >= 16), onClick = {
                if (done) onClose() else approve(code)
            }) { Text(if (done) "Done" else "Link device") }
        },
        dismissButton = { TextButton(onClick = onClose) { Text("Cancel") } },
        title = { Text("Link a device") },
        text = {
            Column {
                Text("1. On the new device, open Skwod and log in to this Skwod with your username and password.\n2. It then shows a code. Scan it here, or type it.\n\nOnly link a device you are holding: it will be able to read your new messages.",
                    style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(12.dp))
                if (!done) {
                    OutlinedButton(onClick = { scanning = true }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Scan the code") }
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(value = code, onValueChange = { code = it }, singleLine = true,
                        placeholder = { Text("XXXX-XXXX-XXXX-XXXX") }, modifier = Modifier.fillMaxWidth())
                }
                if (message.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text(message, style = MaterialTheme.typography.labelSmall, color = if (done) Color(0xFF4ADE80) else Color(0xFFFB923C))
                }
            }
        }
    )
}

/**
 * Licence + third-party acknowledgements. skwod links Signal's libsignal (AGPL-3.0-only), so the
 * app is distributed under the same licence and tells the user where the source is.
 */
@Composable
fun LicensesDialog(onClose: () -> Unit) {
    val entries = listOf(
        Triple("libsignal (libsignal-protocol v0.108.0)", "AGPL-3.0-only · © Signal Messenger, LLC",
            "The Signal Protocol: PQXDH, Double Ratchet + SPQR, Sender Keys, Sealed Sender, safety numbers."),
        Triple("SparsePostQuantumRatchet (spqr), libcrux-ml-kem", "AGPL-3.0-only (spqr) · Apache-2.0 (libcrux)",
            "Post-quantum ratchet and ML-KEM/Kyber used by libsignal."),
        Triple("RustCrypto, curve25519-dalek, ed25519-dalek", "MIT / Apache-2.0 / BSD-3-Clause",
            "Attachment encryption, key backup, metadata sealing, server identity."),
        Triple("SQLCipher, OpenSSL", "BSD-3-Clause · Apache-2.0", "The encrypted on-device cache."),
        Triple("Arti (Tor), rustls, tokio, reqwest, UniFFI, JNA", "MIT / Apache-2.0 / MPL-2.0 / LGPL-2.1",
            "Private address lookups, networking, Kotlin bindings."),
        Triple("iroh", "MIT / Apache-2.0 · © n0, inc.", "The peer-to-peer transport: reaching a host by its key, hole punching, relays."),
        Triple("LiveKit Android SDK", "Apache-2.0", "Voice and video transport (media is end-to-end encrypted with keys Skwod generates)."),
    )
    AlertDialog(
        onDismissRequest = onClose,
        confirmButton = { TextButton(onClick = onClose) { Text("Done") } },
        title = { Text("Licences") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text("Skwod is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License, version 3 only. It comes with NO WARRANTY. Complete corresponding source:",
                    style = MaterialTheme.typography.bodySmall)
                Text("https://github.com/FlayrLabs/skwod", fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                Spacer(Modifier.height(6.dp))
                Text("Skwod is not affiliated with or endorsed by Signal Messenger, LLC.", style = MaterialTheme.typography.labelSmall)
                Spacer(Modifier.height(12.dp))
                entries.forEach { (name, license, note) ->
                    Text(name, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
                    Text(license, style = MaterialTheme.typography.labelSmall)
                    Text(note, style = MaterialTheme.typography.labelSmall, color = Color.White.copy(alpha = 0.6f))
                    Spacer(Modifier.height(8.dp))
                }
            }
        }
    )
}
