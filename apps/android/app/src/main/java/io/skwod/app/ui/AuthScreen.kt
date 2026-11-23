package io.skwod.app

import androidx.compose.foundation.Image
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Turn a failed sign-up / log-in into one sentence a person can act on (never the raw error). */
internal fun authError(e: Exception, signup: Boolean): String {
    if (e is InviteException) return e.message ?: "That doesn't look like a Skwod invite."
    if (e is SkwodIdentityException) return e.message ?: "Couldn't confirm this Skwod. Try again."
    if (e is uniffi.skwod_core.CoreException.UpdateRequired) {
        return "Update required: this Skwod and this app use different encryption versions. Update Skwod, or ask your host to update the server."
    }
    val d = (when (e) {
        is uniffi.skwod_core.CoreException.Engine -> e.detail
        is uniffi.skwod_core.CoreException.Invalid -> e.detail
        else -> e.message ?: ""
    }).lowercase()
    return when {
        d.contains("could not reach") || d.contains("unreachable") || d.contains("timed out") || d.contains("timeout") ->
            "Can't reach your host right now. Their computer may be off, asleep or offline — try again in a moment."
        // A valid invite whose waiting places are taken (the server says so in words): the
        // invite is fine, the host has to let people in. Same sentence as the Apple app.
        d.contains("invite full") -> "This invite already has a lot of people waiting to be let in. Ask your host to approve them (or send you a new invite), then try again."
        d.contains("403") || d.contains("forbidden") -> if (signup) "That invite isn't valid any more. Ask your host for a fresh one." else "Wrong username or password."
        d.contains("409") || d.contains("conflict") -> "That username is taken."
        d.contains("401") || d.contains("unauthorized") -> "Wrong username or password."
        d.contains("429") || d.contains("rate") -> "Too many attempts — wait a minute."
        d.contains("password too short") || d.contains("400") -> "Check the username (a–z, 0–9, _) and password (min 8)."
        d.contains("connect") || d.contains("dns") || d.contains("host") -> "Can't reach that Skwod. Check the invite or address."
        else -> "Something went wrong. Try again."
    }
}

/**
 * Connect to a skwod — visually matched to the iOS AuthView: centered logo tile, segmented Sign
 * up/Log in, and pill fields with leading icons.
 *
 * Joining takes ONE thing from the host: an invite. It can be tapped (`skwod://join/…` opens the
 * app), scanned as a QR code, or pasted. Every route goes through [InviteLink.parse] — the invite
 * only ever PREFILLS this form; the user still chooses a name and password and presses the button.
 * Classic `https://host#code` links and bare `https://` addresses keep working for VPS hosts.
 * Hosting is a Mac / Docker feature, so there's no host option here.
 */
@Composable
fun AuthScreen(onDone: () -> Unit) {
    val ctx = LocalContext.current
    val model = AppModel.get(ctx)
    val scope = rememberCoroutineScope()
    // The app's (adaptive) squid icon, rasterized so Compose can draw it — the one splash of color.
    val logo = remember {
        val d = ctx.packageManager.getApplicationIcon(ctx.packageName)
        val bmp = android.graphics.Bitmap.createBitmap(192, 192, android.graphics.Bitmap.Config.ARGB_8888)
        val canvas = android.graphics.Canvas(bmp)
        d.setBounds(0, 0, 192, 192); d.draw(canvas)
        bmp.asImageBitmap()
    }
    // "Create account" needs an invite; "Log in" (an account made on another device) needs only
    // the address, username and password. Someone who has used a skwod here starts on Log in.
    var signup by remember { mutableStateOf(model.workspaces.isEmpty() && model.knownServers().isEmpty()) }
    var server by remember { mutableStateOf("") }
    var inviteLink by remember { mutableStateOf("") }
    // The invite's code typed by hand, when the link (or host key) came without it. Create account only.
    var code by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var username by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var info by remember { mutableStateOf<String?>(null) }
    var reconnectName by remember { mutableStateOf<String?>(null) }
    var scanning by remember { mutableStateOf(false) }
    // What the host says about the invite in the form, asked BEFORE any name or password is
    // typed: an expired / used / unknown invite is reported here, not after "Create account".
    var inviteProblem by remember { mutableStateOf<String?>(null) }
    var inviteNote by remember { mutableStateOf<String?>(null) }
    var checkingInvite by remember { mutableStateOf(false) }
    // What a link, a scanned code or the clipboard put into the form (as opposed to what the
    // user typed): while the field still holds exactly this, no host is contacted ([InviteDial]).
    var adopted by remember { mutableStateOf<String?>(null) }
    fun mayDial(field: String, address: SkwodAddress): Boolean = InviteDial.mayDial(field, adopted, knownHost = model.workspaceFor(address) != null)

    /**
     * Take an invite from a deep link, a QR scan or the clipboard: validate, then prefill.
     * [fromUser]: the user pressed Scan / Paste, so the mode they picked stays ([AuthForm.modeAfterAdopting]).
     */
    fun adoptInvite(raw: String, fromUser: Boolean = false) {
        val parsed = try { LoginAddress.parse(raw) } catch (e: InviteException) { error = e.message; info = null; return }
        error = null
        signup = AuthForm.modeAfterAdopting(signup, parsed.joinCode != null, fromUser)
        if (signup) {
            inviteLink = raw.trim(); adopted = inviteLink
            info = when {
                parsed.joinCode == null -> "Address ready. Type the invite code your host gave you, then pick a username and password."
                parsed.address is SkwodAddress.P2p -> "Invite ready. Pick a username and password to join."
                else -> "Invite ready for ${Workspace.defaultName(parsed.address.stored)}. Pick a username and password to join."
            }
        } else {
            // Log in: the address is all that is needed; a code in the link is ignored.
            server = parsed.address.stored; adopted = server
            info = "Address ready. Log in with your username and password."
        }
    }

    // A tapped skwod:// link (or one handed over while the app was already open), or a skwod
    // asking to be logged in to again (address + username prefilled).
    LaunchedEffect(model.pendingInvite) {
        model.pendingInvite?.let {
            adoptInvite(it); model.pendingInvite = null
            model.pendingLoginName?.let { name -> if (!signup && username.isEmpty()) username = name }
            model.pendingLoginName = null
        }
    }

    val usernameHint: String? = when {
        username.isEmpty() -> null
        username.length !in 3..32 || !username.all { it.isDigit() || (it in 'a'..'z') || it == '_' } ->
            "Usernames are 3–32 characters: a–z, 0–9, underscore."
        else -> null
    }
    val passwordHint: String? = if (signup && password.isNotEmpty() && password.length < 8)
        "Passwords need at least 8 characters." else null
    // What the Create-account field holds, and the code to sign up with (the link's, or the typed one).
    val signupParsed = if (signup) try { LoginAddress.parse(inviteLink) } catch (_: InviteException) { null } else null
    val linkHasCode = signupParsed?.joinCode != null
    val signupCode = if (signup) AuthForm.signupCode(signupParsed?.joinCode, code) else null
    val formValid = usernameHint == null &&
        AuthForm.canSubmit(signup, if (signup) inviteLink else server, username, password, signupCode) &&
        (!signup || inviteProblem == null)

    // Debounced, classic https skwods only: if the pasted address is a skwod you already belong to
    // (its tunnel address just moved), offer a credential-free Reconnect. A p2p address is a key
    // and never moves, so there is nothing to look up for it.
    val pastedAddr = if (signup) inviteLink.substringBefore("#") else server
    LaunchedEffect(pastedAddr) {
        reconnectName = null
        val a = try { LoginAddress.forLogin(pastedAddr) } catch (_: InviteException) { return@LaunchedEffect }
        if (a !is SkwodAddress.Https || !a.url.startsWith("https://")) return@LaunchedEffect
        // An address that only arrived in a link is not contacted until the user acts.
        if (!mayDial(if (signup) inviteLink else server, a)) return@LaunchedEffect
        delay(600)
        reconnectName = try { model.knownSkwodName(a.url) } catch (_: Exception) { null }
    }

    // Debounced so typing / pasting settles first. The check is unauthenticated and sends only
    // the code to the host the link names; it never joins anything. It runs for what the user
    // typed or pasted into the field themselves — not for a link that was merely opened.
    LaunchedEffect(inviteLink, signupCode, signup) {
        inviteProblem = null; inviteNote = null; checkingInvite = false
        if (!signup) return@LaunchedEffect
        val parsed = try { LoginAddress.parse(inviteLink.trim()) } catch (_: InviteException) { return@LaunchedEffect }
        val code = signupCode ?: return@LaunchedEffect
        // A tapped link only prefills: its host learns nothing (this device's address, that
        // Skwod is installed) until the user presses the button — the join itself then checks.
        if (!mayDial(inviteLink, parsed.address)) { inviteNote = InviteDial.HELD_NOTE; return@LaunchedEffect }
        delay(500)
        checkingInvite = true
        try {
            val check = withContext(Dispatchers.IO) { model.checkInvite(parsed.address, code) }
            inviteProblem = InviteProblems.message(check.valid, check.reason)
            if (check.valid && check.requiresApproval) inviteNote = "After you sign up, the host has to let you in. You'll get in as soon as they do."
        } catch (e: kotlinx.coroutines.CancellationException) { throw e
        } catch (_: Exception) {
            // Could not ask (host off / asleep): say so, but do not block — the join decides.
            inviteNote = "Couldn't reach the host to check this invite yet. Their computer may be off or asleep."
        } finally { checkingInvite = false }
    }

    fun submit() {
        if (busy) return
        error = null
        val raw = (if (signup) inviteLink else server).trim()
        // Log in needs the address only; Create account needs the address and an invite code.
        val address = try { if (signup) LoginAddress.parse(raw).address else LoginAddress.forLogin(raw) }
            catch (e: InviteException) { error = e.message; return }
        val joinCode = if (signup) signupCode ?: run {
            error = "Type the invite code from your host — or choose Log in if you already have an account."
            return
        } else null
        // Classic links may still carry a beacon suffix after the code (address-move lookup).
        val beacon = if (signup && address is SkwodAddress.Https && raw.contains('#')) InviteBeacon.parse(raw.substringAfter('#')) else null
        val name = username.trim().lowercase()
        busy = true
        scope.launch {
            try {
                // Already in this skwod with this account: switch to it, and let the invite's code
                // join one more of its servers — no second account.
                val existing = model.workspaceFor(address)
                if (existing != null && signup && existing.username == name && !existing.isSignedOut) {
                    withContext(Dispatchers.IO) { model.activate(existing) }
                    joinCode?.let { model.joins.begin(it) }
                    onDone(); return@launch
                }
                if (address is SkwodAddress.Https && address.url.startsWith("https://")) {
                    // A skwod you're already in that just moved: reconnect silently (verified
                    // against the pinned key) — no re-login, all history/keys intact.
                    if (model.reconnectIfKnown(address.url)) { onDone(); return@launch }
                    // If it CLAIMS to be a skwod you're in (instanceId match) but failed the pinned-key
                    // proof, it's an impostor echoing public values — refuse rather than send creds there.
                    if (withContext(Dispatchers.IO) { model.impersonatesKnownSkwod(address.url) }) {
                        error = "That address claims to be a Skwod you're in but failed its security check — don't enter your password."
                        return@launch
                    }
                }
                val ok = withContext(Dispatchers.IO) {
                    try {
                        if (signup) model.signUp(address, name, password, joinCode ?: "", beacon?.second, beacon?.third)
                        else model.logIn(address, name, password)
                    } catch (e: Exception) { error = authError(e, signup); false }
                }
                if (ok) { password = ""; onDone() }
            } finally { busy = false }
        }
    }

    // DEBUG e2e hook (compiled out of release): once an invite is in the form, fill in the
    // configured credentials and press the real button.
    LaunchedEffect(inviteLink, server) {
        val creds = E2E.credentials() ?: return@LaunchedEffect
        if (inviteLink.isBlank() && server.isBlank()) return@LaunchedEffect
        delay(1500)
        username = creds.first; password = creds.second
        delay(300)
        submit()
    }

    if (scanning) {
        QrScannerDialog(
            title = "Scan an invite",
            hint = "Point the camera at the QR code your host is showing. Works offline.",
            onResult = { scanning = false; adoptInvite(it, fromUser = true) },
            onClose = { scanning = false })
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 28.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(40.dp))
        // Header — the logo is the one splash of color, everything else is monochrome.
        Image(logo, "Skwod",
            Modifier.size(96.dp).clip(RoundedCornerShape(22.dp))
                .border(1.dp, Color.White.copy(alpha = 0.14f), RoundedCornerShape(22.dp)))
        Spacer(Modifier.height(12.dp))
        Text("Skwod", color = Color.White, fontSize = 36.sp, fontWeight = FontWeight.Bold)
        Text("end-to-end encrypted", color = Color.White.copy(alpha = 0.55f), fontSize = 14.sp)
        Spacer(Modifier.height(22.dp))

        // Segmented Create account / Log in.
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            SegmentedButton(selected = signup, onClick = { if (!signup && inviteLink.isBlank()) inviteLink = server; signup = true; error = null },
                shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)) { Text("Create account") }
            SegmentedButton(selected = !signup, onClick = {
                // The address carries over; the invite's code is simply not needed to log in.
                if (signup && server.isBlank()) server = try { LoginAddress.parse(inviteLink).address.stored } catch (_: InviteException) { "" }
                signup = false; error = null
            },
                shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)) { Text("Log in") }
        }
        Spacer(Modifier.height(6.dp))
        Text(if (signup) "New to this Skwod? You need an invite from its host."
             else "Already have an account (on another device)? Just the address, your username and password — no invite code.",
            color = Color.White.copy(alpha = 0.55f), fontSize = 12.sp, modifier = Modifier.fillMaxWidth(),
            textAlign = androidx.compose.ui.text.style.TextAlign.Center)
        Spacer(Modifier.height(12.dp))

        if (signup) {
            PillField(inviteLink, { inviteLink = it; info = null }, "Invite link or host key", Icons.Filled.Link, KeyboardType.Uri)
            if (inviteLink.isNotBlank() && !linkHasCode) {
                Spacer(Modifier.height(8.dp))
                // Typing is never blocked or rewritten here: the code is tidied up on submit (JoinCode.normalise).
                PillField(code, { code = it; info = null }, "Invite code (e.g. ABCD2345)", Icons.Filled.Key, KeyboardType.Ascii, characters = true)
            }
        } else {
            PillField(server, { server = it; info = null },
                "Skwod address, host key or invite link", Icons.Filled.Dns, KeyboardType.Uri)
        }
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { scanning = true }, modifier = Modifier.weight(1f), shape = RoundedCornerShape(50)) {
                Icon(Icons.Filled.QrCodeScanner, null, modifier = Modifier.size(18.dp)); Spacer(Modifier.width(6.dp)); Text("Scan QR")
            }
            OutlinedButton(onClick = {
                val cm = ctx.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as? android.content.ClipboardManager
                val text = try { cm?.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(ctx)?.toString() } catch (_: Exception) { null }
                if (text.isNullOrBlank()) error = "There's no invite on the clipboard." else adoptInvite(text, fromUser = true)
            }, modifier = Modifier.weight(1f), shape = RoundedCornerShape(50)) {
                Icon(Icons.Filled.ContentPaste, null, modifier = Modifier.size(18.dp)); Spacer(Modifier.width(6.dp)); Text("Paste")
            }
        }
        if (!signup) {
            // One-tap "log back into a skwod you've used" — addresses only, kept across sign-out.
            val known = remember { model.knownServers() }
            if (known.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
                    known.forEach { (address, name) ->
                        Surface(color = Color.White.copy(alpha = 0.08f), shape = RoundedCornerShape(50),
                            modifier = Modifier.padding(end = 8.dp).clickable { server = address }) {
                            Row(Modifier.padding(horizontal = 11.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Filled.History, null, tint = Color.White.copy(alpha = 0.7f), modifier = Modifier.size(14.dp))
                                Spacer(Modifier.width(5.dp))
                                Text(name, color = Color.White.copy(alpha = 0.85f), fontSize = 13.sp, maxLines = 1)
                            }
                        }
                    }
                }
            }
        }
        if (signup && inviteProblem != null) {
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Warning, null, tint = Color(0xFFF87171), modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
                Text(inviteProblem!!, color = Color(0xFFF87171), fontSize = 13.sp)
            }
        } else {
            info?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, color = Color(0xFF4ADE80), fontSize = 13.sp, modifier = Modifier.fillMaxWidth())
            }
            if (signup) (if (checkingInvite) "Checking this invite with the host…" else inviteNote)?.let {
                Spacer(Modifier.height(6.dp))
                Text(it, color = Color.White.copy(alpha = 0.6f), fontSize = 12.sp, modifier = Modifier.fillMaxWidth())
            }
        }
        Spacer(Modifier.height(12.dp))
        PillField(username, { username = it.lowercase() }, "Username", Icons.Filled.AlternateEmail, isError = usernameHint != null)
        usernameHint?.let { FieldHint(it) }
        Spacer(Modifier.height(12.dp))
        PillField(password, { password = it }, "Password", Icons.Filled.Lock, KeyboardType.Password, secure = true, isError = passwordHint != null)
        passwordHint?.let { FieldHint(it) }
        Spacer(Modifier.height(20.dp))

        reconnectName?.let { name ->
            Surface(color = Color.White.copy(alpha = 0.06f), shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp)) {
                Column(Modifier.padding(14.dp)) {
                    Text("You're already in “$name” — it just moved.", color = Color.White, fontSize = 14.sp)
                    Spacer(Modifier.height(8.dp))
                    Button(onClick = {
                        if (busy) return@Button
                        val addr = try { InviteLink.parse(pastedAddr).address.stored } catch (_: InviteException) { return@Button }
                        busy = true; error = null
                        scope.launch {
                            val ok = model.reconnectIfKnown(addr)
                            busy = false
                            if (ok) onDone() else error = "Couldn't verify that address is really “$name.”"
                        }
                    }, enabled = !busy, shape = RoundedCornerShape(50),
                        colors = ButtonDefaults.buttonColors(containerColor = Color.White, contentColor = Color.Black),
                        modifier = Modifier.fillMaxWidth()) {
                        Icon(Icons.Filled.Link, null, modifier = Modifier.size(18.dp)); Spacer(Modifier.width(8.dp))
                        Text(if (busy) "…" else "Reconnect to $name", fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }

        error?.let {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Warning, null, tint = Color(0xFFF87171), modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
                Text(it, color = Color(0xFFF87171), fontSize = 13.sp)
            }
            Spacer(Modifier.height(8.dp))
        }

        Button(
            onClick = { submit() },
            enabled = !busy && formValid,
            shape = RoundedCornerShape(50),
            colors = ButtonDefaults.buttonColors(containerColor = Color.White, contentColor = Color.Black,
                disabledContainerColor = Color.White.copy(alpha = 0.25f), disabledContentColor = Color.Black.copy(alpha = 0.5f)),
            modifier = Modifier.fillMaxWidth().height(52.dp)
        ) { Text(if (busy) "Connecting to your host…" else if (signup) "Create account" else "Log in", fontWeight = FontWeight.SemiBold) }

        Spacer(Modifier.height(10.dp))
        Text(
            (if (signup) "Ask your host for an invite — tap it, scan it, or paste it here."
            else "Log in with the address you joined with — a link, the host key, or pick one above.") +
                (if (signup) PaywallGate.SIGNUP_NOTE else ""),
            color = Color.White.copy(alpha = 0.4f), fontSize = 12.sp,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center
        )
        Spacer(Modifier.height(40.dp))
    }
}

/** A pill-shaped text field with a leading accent icon — the Android peer of iOS `glassField`. */
@Composable
private fun PillField(
    value: String, onValueChange: (String) -> Unit, placeholder: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector, keyboard: KeyboardType = KeyboardType.Text,
    secure: Boolean = false, isError: Boolean = false, characters: Boolean = false,
) {
    OutlinedTextField(
        value, onValueChange,
        placeholder = { Text(placeholder, color = Color.White.copy(alpha = 0.45f)) },
        leadingIcon = { Icon(icon, null, tint = Color.White.copy(alpha = 0.8f)) },
        singleLine = true, isError = isError,
        visualTransformation = if (secure) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        keyboardOptions = KeyboardOptions(keyboardType = keyboard,
            capitalization = if (characters) androidx.compose.ui.text.input.KeyboardCapitalization.Characters else androidx.compose.ui.text.input.KeyboardCapitalization.None,
            autoCorrectEnabled = if (characters) false else null),
        shape = RoundedCornerShape(50),
        colors = OutlinedTextFieldDefaults.colors(
            unfocusedContainerColor = Color.White.copy(alpha = 0.05f),
            focusedContainerColor = Color.White.copy(alpha = 0.07f),
            unfocusedBorderColor = Color.White.copy(alpha = 0.12f),
            focusedBorderColor = Color.White.copy(alpha = 0.30f),
            focusedTextColor = Color.White, unfocusedTextColor = Color.White,
        ),
        modifier = Modifier.fillMaxWidth()
    )
}

@Composable
private fun FieldHint(text: String) {
    Text(text, color = Color(0xFFFACC15).copy(alpha = 0.9f), fontSize = 12.sp,
        modifier = Modifier.fillMaxWidth().padding(start = 12.dp, top = 4.dp))
}
