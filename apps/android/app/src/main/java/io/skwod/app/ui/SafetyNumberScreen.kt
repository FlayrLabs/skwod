package io.skwod.app

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.skwod_core.ContactStatus

private val Amber = Color(0xFFFFA726)
private val Green = Color(0xFF4ADE80)
private val Red = Color(0xFFF87171)

private enum class ScanResult { MATCH, MISMATCH, NOT_A_SAFETY_NUMBER }

/**
 * Out-of-band verification of a contact, Signal-style — the Android peer of Apple's
 * `SafetyNumberView`.
 *
 * There is ONE safety number per pair of accounts: 60 digits derived from every device identity
 * key on both sides. If it is the same number on their screen, nobody is sitting between the two
 * of you, on any of your devices. A hostile host can relay keys, but it cannot make the two
 * numbers agree. Three rules this screen enforces:
 *
 * - **Verification is bound to what was compared.** The number on screen is handed to the core
 *   (`verifyContact`), which re-reads the directory, recomputes it and refuses if it is no longer
 *   that number — a device added between showing the number and confirming it can never end up
 *   "verified".
 * - **The comparison happens outside the conversation.** The only automatic check is a LIVE
 *   camera scan of the other person's screen (never a picture); otherwise the digits are
 *   compared by eye and confirmed explicitly, with a warning not to use anything that was sent
 *   through this conversation.
 * - **The QR code is directional** (`safetyQr`): presenter's fingerprint, then the scanner's.
 *   Scanning your own screen, or a picture of your own code, does not match.
 *
 * [onChanged] is called after the user verifies, or accepts a changed device set, from here (so
 * the conversation can refresh its "sending is paused" banner).
 */
@Composable
fun SafetyNumberDialog(peerName: String, peerUserId: String, onChanged: () -> Unit = {}, onClose: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var number by remember { mutableStateOf<String?>(null) }
    var failed by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<ContactStatus?>(null) }
    var scan by remember { mutableStateOf<ScanResult?>(null) }
    var scanning by remember { mutableStateOf(false) }
    var problem by remember { mutableStateOf<String?>(null) }
    /** The (directional) QR payload shown with [number]. */
    var qr by remember { mutableStateOf<String?>(null) }
    var confirmManual by remember { mutableStateOf(false) }

    // Build 49: every entry point (DM, member list, group people) reconciles the contact book
    // with the core here — for the same skwod's client only.
    // A READ only demotes; a name is raised only after an explicit, successful verification
    // here (`explicitVerify`), and never for a flagged name.
    // `asked`: the binding captured by the caller before its first await; everything here is
    // for that skwod only.
    suspend fun refreshStatus(asked: BoundClient<uniffi.skwod_core.SkwodClient>, explicitVerify: Boolean = false, explicitUnverify: Boolean = false) {
        if (!Asked.holds(asked, model.bound)) return
        val wid = asked.workspaceId
        val st = try { withContext(Dispatchers.IO) { asked.client.contactStatus(peerUserId) } } catch (_: Exception) { null } ?: return
        if (!Asked.holds(asked, model.bound)) return
        status = st
        when {
            explicitVerify && st.verified -> {
                // Gated in the store: a flagged name is not pinned.
                model.contacts.setVerified(wid, peerUserId, true, peerName)
            }
            explicitUnverify -> if (!st.verified) model.contacts.setVerified(wid, peerUserId, false, peerName) else model.contacts.noteStatusRead(wid, peerUserId, true)
            else -> model.contacts.noteStatusRead(wid, peerUserId, st.verified)
        }
    }

    suspend fun compute(asked: BoundClient<uniffi.skwod_core.SkwodClient>? = model.bound) {
        val me = model.session?.userId
        if (me == null || asked == null) { failed = true; return }
        val c = asked.client
        try {
            // ONE number per account: the device id is ignored by the core.
            val n = withContext(Dispatchers.IO) { c.safetyNumber(me, peerUserId, "") }
            if (!Asked.holds(asked, model.bound)) return
            number = n
            val q = try { withContext(Dispatchers.IO) { c.safetyQr(peerUserId) } } catch (_: Exception) { null }
            if (!Asked.holds(asked, model.bound)) return
            qr = q
            failed = false
        } catch (_: Exception) {
            if (!Asked.holds(asked, model.bound)) return
            // No stale number or code on screen; the status is still read (it may demote).
            failed = true; number = null; qr = null
        }
        refreshStatus(asked)
    }

    /**
     * The device set changed while this screen was open: nothing was marked. Show the new number
     * and say so — the comparison has to be done again, with the new number.
     */
    suspend fun changedUnderneath(asked: BoundClient<uniffi.skwod_core.SkwodClient>) {
        scan = null
        compute(asked)
        problem = if ((status?.unvouchedDevices ?: 0u) > 0u)
            "Not verified: the server now lists a device for $peerName that none of their devices vouched for. Decide about it first."
        else "Not verified: the safety number changed while you were comparing — a device was added or removed. The number above is the new one; compare it again."
    }

    /**
     * Ask the core to mark the account verified FOR THE NUMBER ON SCREEN. It recomputes the
     * number and refuses if the device set is no longer the one that number covers.
     */
    suspend fun verify() {
        val asked = model.bound ?: return
        val shown = number ?: return
        problem = null
        try {
            // The record happens only if the skwod is still the one the verify started in.
            val ran = BoundStep.run(asked, { model.bound }, { withContext(Dispatchers.IO) { asked.client.verifyContact(peerUserId, shown) } }) {
                refreshStatus(asked, explicitVerify = true)
            }
            if (ran) onChanged()
        } catch (_: uniffi.skwod_core.CoreException.IdentityChanged) {
            if (Asked.holds(asked, model.bound)) changedUnderneath(asked)
        } catch (_: Exception) {
            if (Asked.holds(asked, model.bound)) problem = "Couldn't mark $peerName verified. Check your connection and try again."
        }
    }

    suspend fun unverify() {
        val asked = model.bound ?: return
        try { withContext(Dispatchers.IO) { asked.client.unverifyContact(peerUserId) } } catch (_: Exception) {}
        if (!Asked.holds(asked, model.bound)) return
        refreshStatus(asked, explicitUnverify = true)
        onChanged()
    }

    /** Continue with the devices the directory lists now (clears "verified"). */
    suspend fun accept() {
        val asked = model.bound ?: return
        problem = null
        try {
            // Exactly the set this screen showed (audit L2).
            withContext(Dispatchers.IO) { asked.client.acceptIdentityChange(peerUserId, "", status?.acceptFingerprint ?: "") }
            if (!Asked.holds(asked, model.bound)) return
            compute(asked)
            onChanged()
        } catch (_: uniffi.skwod_core.CoreException.IdentityChanged) {
            if (!Asked.holds(asked, model.bound)) return
            compute(asked)
            problem = "Their devices changed while you were deciding. Nothing was accepted — look again and decide."
        } catch (_: Exception) { if (Asked.holds(asked, model.bound)) problem = "Couldn't accept the change. Check your connection and try again." }
    }

    /** A live camera scan of the other person's screen. */
    suspend fun check(scanned: String) {
        val asked = model.bound ?: return
        val shown = number ?: return
        try {
            val matched = withContext(Dispatchers.IO) { asked.client.checkSafetyQr(peerUserId, scanned) }
            if (!Asked.holds(asked, model.bound)) return
            if (matched == null) { scan = ScanResult.NOT_A_SAFETY_NUMBER; return }
            // The code matched the number the core holds NOW; it must also be the one on screen.
            if (matched != shown) { changedUnderneath(asked); return }
            scan = ScanResult.MATCH
            verify()
        } catch (_: uniffi.skwod_core.CoreException.IdentityChanged) {
            if (Asked.holds(asked, model.bound)) scan = ScanResult.MISMATCH
        } catch (_: Exception) {
            if (Asked.holds(asked, model.bound)) problem = "Couldn't check that code. Check your connection and try again."
        }
    }

    LaunchedEffect(peerUserId) { compute() }

    // A Dialog inside a Dialog does not show on Android, so the scanner replaces this one.
    if (scanning) {
        QrScannerDialog("Scan $peerName's code",
            "Point the camera at the code on $peerName's own screen — not at a picture of it.",
            onResult = { scanning = false; scope.launch { check(it) } }, onClose = { scanning = false })
        return
    }
    if (confirmManual) {
        AlertDialog(
            onDismissRequest = { confirmManual = false },
            title = { Text("Did all 60 digits match?") },
            text = { Text("Only confirm if you read the number on $peerName's own screen — in person, or read aloud over a phone or video call that does not go through this Skwod. A number or screenshot sent in this conversation does not count: whoever could be in the middle would have chosen it.") },
            confirmButton = { TextButton(onClick = { confirmManual = false; scope.launch { verify() } }) { Text("Yes, they match — verify") } },
            dismissButton = { TextButton(onClick = { confirmManual = false }) { Text("Cancel") } },
        )
        return
    }

    val verified = status?.verified == true
    Dialog(onDismissRequest = onClose) {
        Surface(color = GlassDialogTone, shape = RoundedCornerShape(20.dp)) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(if (verified) Icons.Filled.VerifiedUser else Icons.Filled.Shield, null,
                    tint = if (verified) Green else SkAccent, modifier = Modifier.size(44.dp))
                Spacer(Modifier.height(8.dp))
                Text(if (verified) "$peerName is verified" else "Verify $peerName", color = Color.White,
                    style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
                Spacer(Modifier.height(8.dp))
                val devices = status?.devices?.toInt() ?: 0
                val deviceNote = when { devices <= 0 -> ""; devices == 1 -> " (they have 1 device)"; else -> " (they have $devices devices)" }
                Text("This is the one safety number you share with $peerName — it covers all of their devices and all of yours$deviceNote. If it is the same number on their screen, nobody is in the middle.",
                    style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center, color = Color.White.copy(alpha = 0.65f))

                status?.takeIf { it.sendsHeld || it.unvouchedDevices > 0u }?.let { s ->
                    Spacer(Modifier.height(14.dp))
                    ChangedCard(peerName, s, onAccept = { scope.launch { accept() } })
                }

                Spacer(Modifier.height(16.dp))
                val n = number
                when {
                    n != null -> {
                        qr?.let { QrImage(it, sizeDp = 190); Spacer(Modifier.height(12.dp)) }
                        Surface(color = GlassCardTone, shape = RoundedCornerShape(14.dp)) {
                            Text(SafetyNumberFormat.grouped(n), fontFamily = FontFamily.Monospace, fontSize = 16.sp,
                                fontWeight = FontWeight.Medium, color = Color.White, textAlign = TextAlign.Center, lineHeight = 24.sp,
                                modifier = Modifier.padding(14.dp).semantics { contentDescription = "Safety number $n" })
                        }
                        Spacer(Modifier.height(10.dp))
                        // The comparison only means something if it bypasses the thing being checked.
                        Text("Compare in person, or over a channel that is not this Skwod. Never compare using a number, screenshot or code sent in this conversation — that is exactly what someone in the middle could replace.",
                            color = Color.White.copy(alpha = 0.75f), style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.fillMaxWidth().background(Color.White.copy(alpha = 0.06f), RoundedCornerShape(12.dp)).padding(12.dp))
                        scan?.let { r ->
                            Spacer(Modifier.height(10.dp))
                            val (tint, text) = when (r) {
                                ScanResult.MATCH -> Green to "The codes match. This is $peerName, and nobody is in the middle."
                                ScanResult.MISMATCH -> Red to "The code DOES NOT match. Don't mark $peerName verified. Make sure you scanned the code on $peerName's screen for their conversation with you (your own code never matches). If you did, someone may be intercepting this conversation."
                                ScanResult.NOT_A_SAFETY_NUMBER -> Amber to "That isn't a current Skwod safety number code. Ask $peerName to open this same screen and scan the code shown there."
                            }
                            Text(text, color = tint, style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.fillMaxWidth().background(tint.copy(alpha = 0.12f), RoundedCornerShape(12.dp)).padding(12.dp))
                        }
                        Spacer(Modifier.height(10.dp))
                        val blockedByDevice = (status?.unvouchedDevices ?: 0u) > 0u
                        if (verified) {
                            Text("You verified $peerName for the devices they have now. If their devices ever change, Skwod pauses sending and asks you to check again.",
                                color = Green, style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
                            TextButton(onClick = { scope.launch { unverify() } }) { Text("Remove verification") }
                        } else {
                            Button(onClick = { scan = null; scanning = true }, enabled = !blockedByDevice, modifier = Modifier.fillMaxWidth()) {
                                Icon(Icons.Filled.QrCodeScanner, null, modifier = Modifier.size(18.dp)); Spacer(Modifier.width(6.dp))
                                Text("Scan the code on $peerName's screen")
                            }
                            OutlinedButton(onClick = { confirmManual = true }, enabled = !blockedByDevice, modifier = Modifier.fillMaxWidth()) {
                                Text("I compared the digits myself…")
                            }
                            Text(if (blockedByDevice) "Decide about the unconfirmed device above before verifying." else "Verifying covers every device $peerName has now.",
                                style = MaterialTheme.typography.labelSmall, color = Color.White.copy(alpha = 0.5f), textAlign = TextAlign.Center)
                        }
                    }
                    failed -> Text("Couldn't work out a safety number. $peerName may not have set up a device yet, or you're offline.",
                        style = MaterialTheme.typography.labelSmall, color = Amber, textAlign = TextAlign.Center)
                    else -> CircularProgressIndicator(color = SkAccent)
                }
                problem?.let {
                    Spacer(Modifier.height(8.dp))
                    Text(it, color = Amber, style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center)
                }
                Spacer(Modifier.height(12.dp))
                TextButton(onClick = onClose) { Text("Done") }
            }
        }
    }
}

/** A verified contact's devices changed, or the server lists a device nobody vouched for. */
@Composable
private fun ChangedCard(peerName: String, s: ContactStatus, onAccept: () -> Unit) {
    Column(Modifier.fillMaxWidth().background(Amber.copy(alpha = 0.10f), RoundedCornerShape(14.dp))
        .border(1.dp, Amber.copy(alpha = 0.35f), RoundedCornerShape(14.dp)).padding(14.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.GppMaybe, null, tint = Amber, modifier = Modifier.size(18.dp)); Spacer(Modifier.width(6.dp))
            Text(if (s.sendsHeld) "Sending to $peerName is paused" else "Unconfirmed device", color = Amber, fontWeight = FontWeight.SemiBold)
        }
        Spacer(Modifier.height(8.dp))
        val parts = ArrayList<String>()
        if (s.sendsHeld) parts.add("You verified $peerName, and since then their devices changed — one was added, removed or reinstalled. The safety number below is the NEW one. Until you check it, nothing you write is sent to them.")
        if (s.unvouchedDevices > 0u) parts.add("The server lists ${if (s.unvouchedDevices == 1u) "a device" else "${s.unvouchedDevices} devices"} for $peerName that none of their own devices vouched for. That is what an impostor's device would look like. It is not part of the number below, gets nothing from you, and what it sends is held.")
        parts.add("Compare the number with $peerName and mark it verified, or — if you would rather not check — accept the change. Accepting leaves $peerName unverified.")
        Text(parts.joinToString("\n\n"), color = Color.White.copy(alpha = 0.8f), style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = onAccept, modifier = Modifier.fillMaxWidth()) {
            Text(if (s.sendsHeld) "Accept the change without verifying" else "Accept this device")
        }
    }
}
