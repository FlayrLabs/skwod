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

/**
 * Profile → Devices → "Add a device" (build 48), on a device already signed in. Registers an
 * offer with the server (device-signed) and shows it as a QR the new device scans from its first
 * screen: this skwod's key + home relay, the account, and a fresh one-time code valid for five
 * minutes (core `pairing.rs`). No password, token or key. When the new device asks — without a
 * password — it shows five emoji and this dialog shows four sets: the person picks the one on the
 * new device (a wrong pick refuses it), or "None of these". One offer approves one device.
 */
@Composable
fun AddDeviceDialog(onClose: () -> Unit) {
    val ctx = LocalContext.current
    val model = AppModel.get(ctx)
    val scope = rememberCoroutineScope()
    var offer by remember { mutableStateOf<uniffi.skwod_core.PairingOffer?>(null) }
    var qr by remember { mutableStateOf<String?>(null) }
    var candidate by remember { mutableStateOf<uniffi.skwod_core.PairingCandidate?>(null) }
    var error by remember { mutableStateOf("") }
    var done by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var attempt by remember { mutableStateOf(0) }
    fun now(): ULong = (System.currentTimeMillis() / 1000).toULong()

    LaunchedEffect(attempt) {
        error = ""; candidate = null; offer = null; qr = null
        val w = model.current
        val name = w?.username
        val uid = w?.userId
        val c = model.client
        if (c == null || name == null || uid == null) { error = "Not connected."; return@LaunchedEffect }
        // From the host itself: whether it is reachable by key, and lets devices pair by QR.
        val info = try { withContext(Dispatchers.IO) { c.instanceP2p() } } catch (e: Exception) { error = "Couldn't reach your Skwod. Check your connection and try again."; return@LaunchedEffect }
        if (info == null) { error = "This Skwod isn't reachable by its key, so adding a device by QR isn't available. Use “Link a device…” instead."; return@LaunchedEffect }
        if (!info.qrPairing) { error = "This Skwod's host hasn't turned on adding devices by QR. Use “Link a device…” instead."; return@LaunchedEffect }
        val o = try {
            val made = uniffi.skwod_core.pairingNewOffer(info.nodeId, info.relayUrl ?: RelayHints.get(info.nodeId), name, uid, now())
            // The server accepts requests only for offers a device of the account registered.
            withContext(Dispatchers.IO) { c.registerPairingOffer(made) }
            made
        } catch (e: Exception) { error = coreErrorDetail(e) ?: "Couldn't make a code. Try again."; return@LaunchedEffect }
        qr = uniffi.skwod_core.pairingQrEncode(o); offer = o
        while (candidate == null && !done) {
            try {
                candidate = withContext(Dispatchers.IO) { c.pairingCandidate(o, now()) }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                error = if (now() > o.expiresAt) "That code expired." else (coreErrorDetail(e) ?: "That code can't be used any more.")
                offer = null; qr = null
                return@LaunchedEffect
            }
            if (candidate == null) delay(2000)
        }
    }

    AlertDialog(
        onDismissRequest = onClose,
        confirmButton = { TextButton(onClick = onClose) { Text(if (done) "Done" else "Cancel") } },
        title = { Text("Add a device") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally) {
                val cand = candidate
                when {
                    done -> Text("Linked. The new device is setting itself up.", textAlign = TextAlign.Center)
                    cand != null -> {
                        Text(PairingCopy.PICK_TITLE, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
                        Spacer(Modifier.height(10.dp))
                        for (set in cand.choices) {
                            OutlinedButton(enabled = !busy, modifier = Modifier.fillMaxWidth(), onClick = {
                                val o = offer ?: return@OutlinedButton
                                busy = true
                                scope.launch {
                                    try {
                                        val ok = withContext(Dispatchers.IO) { model.client!!.approvePairing(o, cand, set, now()) }
                                        if (ok) done = true else { error = "That request is gone. Make a new code and scan again."; candidate = null; offer = null; qr = null }
                                    } catch (e: Exception) {
                                        error = coreErrorDetail(e) ?: "Couldn't approve. Make a new code and try again."
                                        candidate = null; offer = null; qr = null
                                    } finally { busy = false }
                                }
                            }) { Text(set, fontSize = 28.sp) }
                            Spacer(Modifier.height(6.dp))
                        }
                        Text(PairingCopy.PICK_HINT, style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center)
                        TextButton(enabled = !busy, onClick = {
                            val o = offer ?: return@TextButton
                            scope.launch {
                                try { withContext(Dispatchers.IO) { model.client?.denyPairing(o, cand) } } catch (_: Exception) {}
                                candidate = null; offer = null; qr = null
                                error = "Not added. If that wasn't a device of yours, nothing reached it. Make a new code to try again."
                            }
                        }) { Text(PairingCopy.NONE_OF_THESE) }
                    }
                    qr != null -> {
                        Text("On the new device, open Skwod and tap “Scan from your other device”.",
                            style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
                        Spacer(Modifier.height(12.dp))
                        QrImage(qr!!, sizeDp = 200)
                        Spacer(Modifier.height(10.dp))
                        Text("Waiting for the new device… No password is needed there: you approve it here. The code works once, for five minutes.",
                            style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center)
                    }
                    error.isEmpty() -> CircularProgressIndicator()
                }
                if (error.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text(error, color = Color(0xFFFB923C), style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center)
                    TextButton(onClick = { attempt++ }) { Text("Make a new code") }
                }
            }
        }
    )
}

/**
 * The NEW device's half of "Add a device" by QR (build 48), after scanning the QR another device
 * shows. Never asks for a password. Before dialling it asks "Join <skwod> as <username>?" (the
 * skwod named only by a workspace this device has, else by the host's short key); then it shows
 * five emoji once the other device has seen it, and the person picks the same five there. Once
 * approved it says so, with the host's key, before entering. Cancel, denial and expiry remove
 * what it set up.
 */
@Composable
fun PairNewDeviceDialog(offer: uniffi.skwod_core.PairingOffer, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val model = AppModel.get(ctx)
    val scope = rememberCoroutineScope()
    var joined by remember { mutableStateOf(false) }
    var started by remember { mutableStateOf(false) }
    var emoji by remember { mutableStateOf<String?>(null) }
    var approved by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var finishing by remember { mutableStateOf(false) }
    var run by remember { mutableStateOf<AppModel.PairingRun?>(null) }
    var left by remember { mutableStateOf(0L) }
    val mine = model.workspaces.firstOrNull { it.nodeId == offer.nodeId }
    val shortKey = InviteLink.shortKey(offer.nodeId)

    LaunchedEffect(offer.code, joined) {
        if (!joined) return@LaunchedEffect
        try {
            val r = withContext(Dispatchers.IO) { model.pairingStart(offer) }
            run = r; started = true
            while (true) {
                val now = System.currentTimeMillis() / 1000
                left = offer.expiresAt.toLong() - now
                if (now > offer.expiresAt.toLong() + 60) {
                    model.pairingDrop(r)
                    error = "The code expired before it was approved. Make a new one on your other device."
                    return@LaunchedEffect
                }
                when (val step = withContext(Dispatchers.IO) { model.pairingPoll(r) }) {
                    is AppModel.PairStep.Waiting -> {}
                    is AppModel.PairStep.Confirm -> emoji = step.emoji
                    is AppModel.PairStep.Approved -> { approved = true; return@LaunchedEffect }
                }
                delay(2000)
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            run?.let { model.pairingDrop(it) }
            error = PairingCopy.failure(coreErrorDetail(e) ?: e.message ?: "Couldn't reach that Skwod. Check your connection and try again.")
        }
    }

    AlertDialog(
        onDismissRequest = {},
        confirmButton = {
            when {
                error == null && !joined -> Button(onClick = { joined = true }) { Text("Continue") }
                error == null && approved -> Button(enabled = !finishing, onClick = {
                    val r = run ?: return@Button
                    finishing = true
                    scope.launch {
                        try {
                            if (withContext(Dispatchers.IO) { model.pairingEnter(r) }) onClose() else { error = PairingCopy.NOT_APPROVED; finishing = false }
                        } catch (e: Exception) {
                            error = PairingCopy.failure(coreErrorDetail(e) ?: e.message ?: "Couldn't finish. Try again."); finishing = false
                        }
                    }
                }) { Text("Continue") }
                else -> {}
            }
        },
        dismissButton = {
            TextButton(enabled = !finishing, onClick = { run?.let { model.pairingDrop(it) }; onClose() }) {
                Text(if (error != null) "Close" else "Cancel")
            }
        },
        title = { Text("Add this device") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally) {
                Text(PairingCopy.header(shortKey, offer.username, mine != null),
                    fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
                Spacer(Modifier.height(12.dp))
                val e = emoji
                when {
                    error != null -> Text(error!!, color = Color(0xFFFB923C), style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
                    !joined -> {
                        Text(PairingCopy.joinPrompt(mine?.name, shortKey, offer.username), style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
                        Spacer(Modifier.height(8.dp))
                        Text(PairingCopy.JOIN_DETAIL, style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center)
                    }
                    approved -> Text(PairingCopy.approved(shortKey), color = Color(0xFF4ADE80), fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
                    !started -> { CircularProgressIndicator(); Spacer(Modifier.height(6.dp)); Text("Reaching the Skwod…", style = MaterialTheme.typography.labelSmall) }
                    e == null -> { CircularProgressIndicator(); Spacer(Modifier.height(6.dp)); Text(PairingCopy.WAITING_FOR_OTHER, style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center) }
                    else -> {
                        Text(e, fontSize = 36.sp)
                        Spacer(Modifier.height(10.dp))
                        Text(PairingCopy.CONFIRM, style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
                        Spacer(Modifier.height(8.dp))
                        Text("Waiting for approval · %d:%02d".format(maxOf(0, left) / 60, maxOf(0, left) % 60), style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }
    )
}
