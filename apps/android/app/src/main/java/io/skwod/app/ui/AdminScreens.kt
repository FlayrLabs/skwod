package io.skwod.app

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.sp
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import kotlinx.coroutines.delay
import uniffi.skwod_core.MemberInfo
import uniffi.skwod_core.RoleInfo

/** The permission bitmask, mirrored from the server's spec (perms.rs). Matches the iOS `Perm` enum. */
val PERMISSION_ENTRIES: List<Pair<String, Long>> = listOf(
    "Administrator (everything)" to 8192L,
    "Manage channels" to 1L,
    "Manage roles" to 2L,
    "Manage server" to 4L,
    "Kick members" to 8L,
    "Ban members" to 16L,
    "Manage messages" to 32L,
    "Manage invites" to 1024L,
    "Send messages" to 64L,
    "Attach files" to 256L,
    "Add reactions" to 512L,
    "Mention everyone" to 16384L,
)

fun permissionSummary(mask: Long): String {
    if (mask and 8192L != 0L) return "Administrator"
    val names = PERMISSION_ENTRIES.filter { it.second != 8192L && mask and it.second != 0L }.map { it.first }
    return if (names.isEmpty()) "No permissions"
    else names.take(3).joinToString(", ") + if (names.size > 3) " +${names.size - 3}" else ""
}

/**
 * The server's member roster with live presence (online/offline groups + presence dots) — the mobile
 * peer of the macOS members panel. Tap a member for host moderation: toggle roles, kick, or delete
 * the account (the server enforces that only the instance owner may kick/delete).
 */
@Composable
fun MembersSheet(serverId: String, serverName: String, onClose: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    val members = remember { mutableStateListOf<PresenceMember>() }
    val roles = remember { mutableStateListOf<RoleInfo>() }
    var sheetFor by remember { mutableStateOf<PresenceMember?>(null) }
    var confirmKick by remember { mutableStateOf<PresenceMember?>(null) }
    var blocking by remember { mutableStateOf<SafetyTarget?>(null) }
    var reporting by remember { mutableStateOf<SafetyTarget?>(null) }
    var confirmBan by remember { mutableStateOf<PresenceMember?>(null) }
    var confirmDelete by remember { mutableStateOf<PresenceMember?>(null) }
    var confirmDeleteBan by remember { mutableStateOf<PresenceMember?>(null) }
    // Build 49: "Verify safety number" from the member list (not only from a DM).
    var verifying by remember { mutableStateOf<PresenceMember?>(null) }
    verifying?.let { m ->
        SafetyNumberDialog(model.contacts.shown(m.userId, m.username).name, m.userId, onClose = { verifying = null })
    }
    var status by remember { mutableStateOf<String?>(null) }
    var tick by remember { mutableStateOf(0) }

    // Re-read when the relay says the server's membership changed (someone joined, someone asked
    // to join) and on a slow timer; live presence dots come from the socket's presence events.
    LaunchedEffect(serverId, tick) {
        roles.clear(); roles.addAll(try { withContext(Dispatchers.IO) { model.client!!.listRoles(serverId) } } catch (_: Exception) { emptyList() })
        model.realtime.refreshLoop(30_000, match = { (it.topic == "server:$serverId" && it.event != "presence") || it.event == "join_request" }) {
            val askedAt = model.realtime.presenceClock()
            val fresh = model.listPresenceMembers(serverId)
            if (fresh.isNotEmpty()) {
                members.clear(); members.addAll(fresh)
                model.realtime.seedPresence(fresh.associate { it.userId to it.status }, askedAt)
            }
            model.waiting.refresh(serverId)
        }
    }

    // Poll results overlaid with live socket presence, so flips are instant (no 10s poll wait).
    // Reads realtime.presence (Compose state) during composition → auto-recomposes.
    model.realtime.unheard.value
    val live = members.map { it.copy(status = model.realtime.status(it.userId)) }
    // Someone the server lists but who is still waiting to be let in is not shown as a member.
    val waiting = model.waiting.waiting(serverId)
    val heldIds = waiting.map { it.userId }.toSet()
    val accepted = live.filter { it.userId !in heldIds }
    val groups = PresenceRoster.groups(accepted, model.realtime.connected.value) { it.status }
    val online = groups.online
    val offline = groups.offline

    Column(Modifier.fillMaxSize().padding(horizontal = 8.dp)) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onClose) { Icon(Icons.Filled.ArrowBack, "Back", tint = Color.White) }
            Text("Members — $serverName", color = Color.White, style = MaterialTheme.typography.titleMedium)
        }
        status?.let { Text(it, color = Color(0xFFFFA726), style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(horizontal = 12.dp)) }
        LazyColumn {
            if (waiting.isNotEmpty()) {
                item {
                    WaitingToJoinSection(waiting, problem = model.waiting.problem, isBusy = { model.waiting.isBusy(it) },
                        onLetIn = { w -> scope.launch { model.waiting.letIn(w, serverId); tick++ } },
                        onDecline = { w -> scope.launch { model.waiting.decline(w, serverId); tick++ } })
                }
            }
            if (online.isNotEmpty()) {
                item { MemberGroupHeader("Online — ${online.size}") }
                items(online) { m -> MemberRow(m, onVerify = { verifying = m }, onClick = { sheetFor = m }) }
            }
            if (offline.isNotEmpty()) {
                item { MemberGroupHeader("Offline — ${offline.size}") }
                items(offline) { m -> MemberRow(m, dim = true, onVerify = { verifying = m }, onClick = { sheetFor = m }) }
            }
            if (groups.unknown.isNotEmpty()) {
                item { MemberGroupHeader(PresenceRoster.unknownTitle(groups.unknown.size)) }
                items(groups.unknown) { m -> MemberRow(m, onVerify = { verifying = m }, onClick = { sheetFor = m }) }
            }
        }
    }

    blocking?.let { BlockDialog(model, it) { blocking = null } }
    reporting?.let { ReportDialog(model, it) { reporting = null } }
    sheetFor?.let { m ->
        val isMe = m.userId == model.session?.userId
        AlertDialog(
            onDismissRequest = { sheetFor = null },
            confirmButton = { TextButton(onClick = { sheetFor = null }) { Text("Done") } },
            title = { Text(model.contacts.shown(m.userId, m.username).label) },
            text = {
                Column {
                    if (roles.any { !it.isDefault }) {
                        Text("Roles", color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.labelMedium)
                        roles.filter { !it.isDefault }.forEach { r ->
                            val has = m.roleIds.contains(r.roleId)
                            Row(Modifier.fillMaxWidth().clickable {
                                scope.launch {
                                    try {
                                        if (has) withContext(Dispatchers.IO) { model.client!!.removeRole(serverId, m.userId, r.roleId) }
                                        else withContext(Dispatchers.IO) { model.client!!.assignRole(serverId, m.userId, r.roleId) }
                                        tick++; sheetFor = null
                                    } catch (_: Exception) { status = "Couldn't change roles — you need Manage Roles." }
                                }
                            }.padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(if (has) Icons.Filled.CheckCircle else Icons.Filled.RadioButtonUnchecked,
                                    null, tint = if (has) Color(0xFF4ADE80) else Color.White.copy(alpha = 0.4f))
                                Spacer(Modifier.width(8.dp))
                                Text(r.name ?: "role", color = Color.White)
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                    }
                    if (!isMe) {
                        TextButton(onClick = { verifying = m; sheetFor = null }) {
                            Icon(Icons.Filled.VerifiedUser, null, tint = Color.White.copy(alpha = 0.8f)); Spacer(Modifier.width(6.dp))
                            Text("Verify safety number…", color = Color.White)
                        }
                        // For everyone, about anyone: block (or unblock) and report.
                        val blocked = BlockList.contains(m.userId)
                        TextButton(onClick = {
                            sheetFor = null
                            if (blocked) scope.launch { BlockList.setBlocked(model, m.userId, m.username, false)?.let { status = it } }
                            else blocking = SafetyTarget(m.userId, m.username, serverId = serverId)
                        }) {
                            Icon(Icons.Filled.Block, null, tint = Color.White.copy(alpha = 0.8f)); Spacer(Modifier.width(6.dp))
                            Text(if (blocked) "Unblock ${m.username}" else "Block ${m.username}…", color = Color.White)
                        }
                        TextButton(onClick = { reporting = SafetyTarget(m.userId, m.username, serverId = serverId); sheetFor = null }) {
                            Icon(Icons.Filled.Flag, null, tint = Color.White.copy(alpha = 0.8f)); Spacer(Modifier.width(6.dp))
                            Text("Report ${m.username}…", color = Color.White)
                        }
                        TextButton(onClick = { confirmKick = m; sheetFor = null }) {
                            Icon(Icons.Filled.PersonRemove, null, tint = Color(0xFFFACC15)); Spacer(Modifier.width(6.dp))
                            Text("Kick from server", color = Color.White)
                        }
                        TextButton(onClick = { confirmBan = m; sheetFor = null }) {
                            Icon(Icons.Filled.Block, null, tint = Color(0xFFFB923C)); Spacer(Modifier.width(6.dp))
                            Text("Ban from server…", color = Color.White)
                        }
                        TextButton(onClick = { confirmDelete = m; sheetFor = null }) {
                            Icon(Icons.Filled.Delete, null, tint = Color(0xFFF87171)); Spacer(Modifier.width(6.dp))
                            Text("Delete account…", color = Color(0xFFF87171))
                        }
                        TextButton(onClick = { confirmDeleteBan = m; sheetFor = null }) {
                            Icon(Icons.Filled.Block, null, tint = Color(0xFFF87171)); Spacer(Modifier.width(6.dp))
                            Text("Delete and ban…", color = Color(0xFFF87171))
                        }
                    }
                }
            }
        )
    }

    confirmKick?.let { m ->
        AlertDialog(onDismissRequest = { confirmKick = null },
            confirmButton = { TextButton(onClick = {
                val t = m; confirmKick = null
                scope.launch { if (!model.kickMember(serverId, t.userId)) status = "Couldn't kick — only the owner can."; tick++ }
            }) { Text("Kick", color = Color(0xFFFACC15)) } },
            dismissButton = { TextButton(onClick = { confirmKick = null }) { Text("Cancel") } },
            title = { Text("Kick ${model.contacts.shown(m.userId, m.username).label}?") },
            text = { Text("Removes them from this server. Their account survives — they can rejoin with a new invite.") })
    }
    confirmBan?.let { m ->
        AlertDialog(onDismissRequest = { confirmBan = null },
            confirmButton = { TextButton(onClick = {
                val t = m; confirmBan = null
                scope.launch { if (!model.banMember(serverId, t.userId)) status = "Couldn't ban — you need Ban Members."; tick++ }
            }) { Text("Ban", color = Color(0xFFFB923C)) } },
            dismissButton = { TextButton(onClick = { confirmBan = null }) { Text("Cancel") } },
            title = { Text("Ban ${model.contacts.shown(m.userId, m.username).label}?") },
            text = { Text("Removes them AND blocks every invite from readmitting them until you unban. Their account survives.") })
    }
    confirmDelete?.let { m ->
        AlertDialog(onDismissRequest = { confirmDelete = null },
            confirmButton = { TextButton(onClick = {
                val t = m; confirmDelete = null
                scope.launch { if (!model.deleteAccount(t.userId)) status = "Couldn't delete — only the owner can."; tick++ }
            }) { Text("Delete account", color = Color(0xFFF87171)) } },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text("Cancel") } },
            title = { Text("Delete the account of ${model.contacts.shown(m.userId, m.username).label}?") },
            text = { Text("Wipes their account, devices, and memberships — the username is freed for a fresh sign-up.") })
    }
    confirmDeleteBan?.let { m ->
        DeleteAndBanDialog(model.contacts.shown(m.userId, m.username).label, onDismiss = { confirmDeleteBan = null }) {
            confirmDeleteBan = null
            scope.launch { model.deleteAccountAndBan(m.userId)?.let { status = it }; tick++ }
        }
    }
}

/**
 * The instance owner's "Delete and ban" ([AppModel.deleteAccountAndBan]): like deleting the
 * account, and the username and the devices' keys cannot come back. Always confirmed.
 */
@Composable
internal fun DeleteAndBanDialog(name: String, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onConfirm) { Text("Delete and ban", color = Color(0xFFF87171)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
        title = { Text("Delete and ban $name?") },
        text = { Text("Wipes their account, devices, and memberships, and bans them from this Skwod: the username and their devices' keys can't sign up or register here again, and the invite they joined with is revoked. This can't be undone.") })
}

/**
 * The "Waiting to join" block at the top of a server's member list: join requests that need
 * approval and members the server lists but nobody this device trusts has let in.
 */
@Composable
private fun WaitingToJoinSection(
    people: List<WaitingMember>, problem: String?, isBusy: (String) -> Boolean,
    onLetIn: (WaitingMember) -> Unit, onDecline: (WaitingMember) -> Unit,
) {
    val amber = Color(0xFFFFA726)
    Column(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp)
        .background(amber.copy(alpha = 0.08f), RoundedCornerShape(12.dp))
        .border(1.dp, amber.copy(alpha = 0.3f), RoundedCornerShape(12.dp)).padding(14.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.HourglassTop, null, tint = amber, modifier = Modifier.size(16.dp)); Spacer(Modifier.width(6.dp))
            Text("WAITING TO JOIN — ${people.size}", color = amber, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
        }
        Spacer(Modifier.height(6.dp))
        Text("Let someone in only if you know them and expected them. Until then they get none of this server's keys from you.",
            color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
        for (w in people) {
            val busy = isBusy(w.userId)
            // One display for names everywhere: the contact book decides how this one is shown.
            // "Let in" additionally needs the waiting-room verdict (the name must lead to this account).
            val shown = AppModel.get(LocalContext.current).contacts.shown(w.userId, w.username)
            val trusted = w.canLetIn && !shown.strong
            Spacer(Modifier.height(10.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                // An unverified label is never shown as a plain name (or as a monogram of it).
                Monogram(if (trusted) shown.name else "?", size = 32)
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(if (w.displayName.isEmpty()) "Unnamed account" else if (trusted) shown.name else "“${shown.name}”",
                            color = if (shown.strong) Color(0xFFF87171) else if (trusted) Color.White else amber, fontWeight = FontWeight.SemiBold, maxLines = 1)
                        NameTrustMark(shown, words = true)
                        if (w.isNew) {
                            Spacer(Modifier.width(6.dp))
                            Text("NEW", color = Color.Black, fontSize = 9.sp, fontWeight = FontWeight.Bold,
                                modifier = Modifier.background(Color.White.copy(alpha = 0.75f), RoundedCornerShape(50)).padding(horizontal = 5.dp, vertical = 1.dp)
                                    .semantics { contentDescription = "New to you" })
                        }
                    }
                    Text(if (w.source == WaitingMember.Source.REQUEST) "Asked to join" else "Added by the server",
                        color = Color.White.copy(alpha = 0.5f), style = MaterialTheme.typography.labelSmall, maxLines = 1)
                    Text("ID ${w.userId.take(8)} · key ${w.fingerprintLabel}", fontFamily = FontFamily.Monospace, fontSize = 10.sp,
                        color = Color.White.copy(alpha = 0.55f), maxLines = 1)
                }
                if (busy) { CircularProgressIndicator(Modifier.size(18.dp), color = SkAccent); Spacer(Modifier.width(6.dp)) }
            }
            Row(Modifier.padding(start = 42.dp, top = 4.dp)) {
                Button(onClick = { onLetIn(w) }, enabled = !busy && trusted,
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp)) { Text("Let in") }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(onClick = { onDecline(w) }, enabled = !busy,
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp)) { Text("Decline") }
            }
            // The contact book's sentence when it has a flag; else the waiting-room verdict's.
            (shown.warning?.takeIf { shown.flag != ContactTrust.Flag.NONE } ?: io.skwod.app.WaitingTrust.warning(w))?.let { (text, strong) ->
                Text(text, color = if (strong) Color(0xFFF87171) else amber, style = MaterialTheme.typography.labelSmall,
                    fontWeight = if (strong) FontWeight.SemiBold else FontWeight.Normal, modifier = Modifier.padding(start = 42.dp, top = 4.dp))
            }
        }
        problem?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = amber, style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable
private fun MemberGroupHeader(title: String) {
    Text(title.uppercase(), color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelMedium,
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp))
}

@Composable
private fun MemberRow(m: PresenceMember, dim: Boolean = false, onVerify: () -> Unit = {}, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 12.dp, vertical = 6.dp)
        .then(if (dim) Modifier.alpha(0.45f) else Modifier), verticalAlignment = Alignment.CenterVertically) {
        Box {
            AvatarImage(AvatarStore.userKey(m.userId), m.username, size = 32)
            Box(Modifier.align(Alignment.BottomEnd).size(11.dp).clip(CircleShape).background(presenceColor(AppModel.get(LocalContext.current).realtime.dot(m.userId))))
        }
        Spacer(Modifier.width(10.dp))
        // The member list is the server's word: shown through the contact book.
        val model = AppModel.get(LocalContext.current)
        val shown = model.contacts.shown(m.userId, m.username)
        Text(shown.name, color = if (shown.strong) Color(0xFFF87171) else Color.White)
        NameTrustMark(shown, onVerify = if (m.userId == model.session?.userId) null else onVerify)
    }
}

/**
 * Manage a server's roles + their permission bitmasks (role names stay E2EE via the space key), and
 * assign them to members. The server enforces the permission ceiling — a member without "Manage
 * roles"/owner will get an error on create/assign, which surfaces inline.
 */
@Composable
fun RolesSheet(serverId: String, serverName: String, onClose: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    val roles = remember { mutableStateListOf<RoleInfo>() }
    val members = remember { mutableStateListOf<MemberInfo>() }
    var showCreate by remember { mutableStateOf(false) }
    var assignFor by remember { mutableStateOf<RoleInfo?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var tick by remember { mutableStateOf(0) }

    LaunchedEffect(serverId, tick) {
        roles.clear(); roles.addAll(try { withContext(Dispatchers.IO) { model.client!!.listRoles(serverId) } } catch (_: Exception) { emptyList() })
        members.clear(); members.addAll(try { withContext(Dispatchers.IO) { model.client!!.listMembers(serverId) } } catch (_: Exception) { emptyList() })
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onClose) { Icon(Icons.Filled.ArrowBack, "Back", tint = Color.White) }
            Text("Permissions — $serverName", color = Color.White, style = MaterialTheme.typography.titleLarge)
        }
        Text("Roles gate what members can do (create channels, invite, moderate…).",
            color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
        Spacer(Modifier.height(12.dp))
        status?.let { Text(it, color = SkAccent, style = MaterialTheme.typography.labelSmall); Spacer(Modifier.height(8.dp)) }

        roles.forEach { r ->
            Surface(color = GlassCardTone, shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(if (r.isDefault) Icons.Filled.Groups else Icons.Filled.Shield,
                        null, tint = SkAccent.copy(alpha = 0.8f))
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(r.name ?: "everyone", color = Color.White, fontWeight = FontWeight.SemiBold)
                        Text(permissionSummary(r.permissions), color = Color.White.copy(alpha = 0.5f),
                            style = MaterialTheme.typography.labelSmall)
                    }
                    if (!r.isDefault) {
                        TextButton(onClick = { assignFor = r }) { Text("Assign") }
                        IconButton(onClick = {
                            scope.launch {
                                try { withContext(Dispatchers.IO) { model.client!!.deleteRole(r.roleId) }; tick++ }
                                catch (_: Exception) { status = "Couldn't delete — you may lack permission." }
                            }
                        }) { Icon(Icons.Filled.Delete, "Delete", tint = Color(0xFFF87171)) }
                    }
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = { showCreate = true }, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Filled.Add, null); Spacer(Modifier.width(6.dp)); Text("Create a role")
        }
    }

    if (showCreate) {
        CreateRoleDialog(serverId, onClose = { showCreate = false }, onCreated = { showCreate = false; tick++ },
            onError = { status = it })
    }
    assignFor?.let { role ->
        AssignRoleDialog(serverId, role, members, onClose = { assignFor = null }, onError = { status = it })
    }
}

@Composable
private fun CreateRoleDialog(serverId: String, onClose: () -> Unit, onCreated: () -> Unit, onError: (String) -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf("") }
    var mask by remember { mutableStateOf(0L) }
    var busy by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        confirmButton = {
            TextButton(onClick = {
                if (busy) return@TextButton
                busy = true
                scope.launch {
                    try { withContext(Dispatchers.IO) { model.client!!.createRole(serverId, name.trim(), mask) }; onCreated() }
                    catch (_: Exception) { onError("Couldn't create the role — you may lack permission.") }
                    busy = false
                }
            }, enabled = !busy && name.isNotBlank()) { Text(if (busy) "…" else "Create") }
        },
        dismissButton = { TextButton(onClick = onClose, enabled = !busy) { Text("Cancel") } },
        title = { Text("Create a role") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                OutlinedTextField(name, { name = it }, label = { Text("Role name") }, singleLine = true)
                Spacer(Modifier.height(8.dp))
                PERMISSION_ENTRIES.forEach { (label, bit) ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = mask and bit != 0L, onCheckedChange = {
                            mask = if (it) mask or bit else mask and bit.inv()
                        })
                        Text(label, color = Color.White, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    )
}

@Composable
private fun AssignRoleDialog(serverId: String, role: RoleInfo, members: List<MemberInfo>,
                             onClose: () -> Unit, onError: (String) -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    AlertDialog(
        onDismissRequest = onClose,
        confirmButton = { TextButton(onClick = onClose) { Text("Done") } },
        title = { Text("Assign ${role.name ?: "role"}") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                if (members.isEmpty()) Text("No members yet.", color = Color.White.copy(alpha = 0.5f))
                members.forEach { m ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                        // Server-supplied names go through the contact book here too.
                        val shown = model.contacts.shown(m.userId, m.username)
                        Monogram(shown.name, size = 28); Spacer(Modifier.width(10.dp))
                        Row(Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) {
                            Text(shown.name, color = if (shown.strong) Color(0xFFF87171) else Color.White, maxLines = 1)
                            NameTrustMark(shown)
                        }
                        TextButton(onClick = {
                            scope.launch {
                                try { withContext(Dispatchers.IO) { model.client!!.assignRole(serverId, m.userId, role.roleId) } }
                                catch (_: Exception) { onError("Couldn't assign — you may lack permission.") }
                            }
                        }) { Text("Assign") }
                    }
                }
            }
        }
    )
}

/**
 * Skwod-level settings: where this device stores data, and an erase button. Account moderation and
 * the desktop "reveal in Finder" affordance are host/desktop features; on mobile the data lives in
 * the app's private, encrypted storage that only this app can read.
 */
@Composable
fun SkwodSettingsSheet(onClose: () -> Unit, onSignOut: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var showErase by remember { mutableStateOf(false) }
    var showReports by remember { mutableStateOf(false) }
    // Captured when the confirmation OPENS: the binding, the servers and the skwod's name; keyed
    // on the skwod, so a switch dismisses it.
    var confirmClearServer by remember(model.current?.id) { mutableStateOf<ClearAllRequest<BoundClient<uniffi.skwod_core.SkwodClient>>?>(null) }
    // Owner-only: accounts + who may create servers. `accounts == null` until loaded / if not owner.
    var accounts by remember { mutableStateOf<List<Account>?>(null) }
    val creators = remember { mutableStateListOf<String>() }
    var pendingDelete by remember { mutableStateOf<Account?>(null) }
    var pendingDeleteBan by remember { mutableStateOf<Account?>(null) }
    var tick by remember { mutableStateOf(0) }

    LaunchedEffect(tick) {
        accounts = model.listAccounts()
        creators.clear(); model.listServerCreators()?.let { list -> creators.addAll(list.map { it.first }) }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onClose) { Icon(Icons.Filled.ArrowBack, "Back", tint = Color.White) }
            Text("Skwod settings", color = Color.White, style = MaterialTheme.typography.titleLarge)
        }
        Spacer(Modifier.height(16.dp))

        // The owner's reports inbox: there when something was reported, and always for the host.
        if (ReportRules.entryVisible(model.reports.list.size, model.isInstanceOwner)) {
            Surface(color = GlassCardTone, shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth().clickable { showReports = true }) {
                Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Flag, null, tint = Color.White.copy(alpha = 0.8f)); Spacer(Modifier.width(10.dp))
                    Text("Reports", color = Color.White, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                    ReportsBadge(model.reports.list.size)
                }
            }
            Spacer(Modifier.height(14.dp))
        }

        // Owner-only, and only while another call server is saved: what calls use, and the way back.
        if (accounts != null) VoiceServerCard()

        // Owner-only: manage accounts + server-creation grants (mirrors the iOS accountsCard).
        accounts?.let { list ->
            Surface(color = GlassCardTone, shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Accounts on this Skwod", color = Color.White, fontWeight = FontWeight.SemiBold)
                    Text("Everyone who signed up here. Toggle who may create servers; delete frees the username.",
                        color = Color.White.copy(alpha = 0.5f), style = MaterialTheme.typography.labelSmall)
                    Spacer(Modifier.height(8.dp))
                    list.forEach { a ->
                        val isMe = a.userId == model.session?.userId
                        Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                            val shown = model.contacts.shown(a.userId, a.username)
                            Monogram(shown.name, size = 28); Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(shown.name, color = if (shown.strong) Color(0xFFF87171) else Color.White, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
                                    NameTrustMark(shown)
                                }
                                Text(if (isMe) "you · owner" else if (a.isMember) "member" else "never joined a server",
                                    color = Color.White.copy(alpha = 0.45f), style = MaterialTheme.typography.labelSmall)
                            }
                            if (!isMe) {
                                // Grant/revoke server creation.
                                val granted = creators.contains(a.userId)
                                TextButton(onClick = {
                                    scope.launch {
                                        if (granted) model.revokeServerCreator(a.userId) else model.grantServerCreator(a.userId)
                                        tick++
                                    }
                                }) { Text(if (granted) "Can create ✓" else "Grant create",
                                    color = if (granted) Color(0xFF4ADE80) else SkAccent,
                                    style = MaterialTheme.typography.labelSmall) }
                                IconButton(onClick = { pendingDelete = a }) {
                                    Icon(Icons.Filled.Delete, "Delete account", tint = Color(0xFFF87171))
                                }
                            }
                        }
                    }
                }
            }
            Spacer(Modifier.height(14.dp))
        }

        Surface(color = GlassCardTone, shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                Text("Where your data lives", color = Color.White, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(6.dp))
                Text("Everything on this device — your keys, messages, and cached files — is stored in " +
                    "Skwod's private app storage, encrypted at rest. No other app can read it, and it never " +
                    "leaves the device except as end-to-end-encrypted ciphertext to your host.",
                    color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.bodySmall)
            }
        }
        Spacer(Modifier.height(14.dp))

        // Owner-only: wipe all message content across this skwod's servers, keeping members + roles.
        if (model.isInstanceOwner) {
            Surface(color = GlassCardTone, shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Clear all messages", color = Color.White, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(6.dp))
                    Text("Permanently deletes every message, story, and post across all of this Skwod's channels, " +
                        "for everyone. Channels, members, and roles stay. This can't be undone.",
                        color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(10.dp))
                    Button(onClick = {
                        val asked = model.bound
                        if (asked != null) confirmClearServer = ClearAllRequest(asked,
                            model.chat.spaces.map { it.serverId }.filter { it.isNotEmpty() && it != "demo" }.distinct(),
                            model.current?.displayName ?: "this Skwod")
                    },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF87171))) {
                        Icon(Icons.Filled.ClearAll, null, tint = Color.Black); Spacer(Modifier.width(6.dp))
                        Text("Clear all messages", color = Color.Black)
                    }
                }
            }
            Spacer(Modifier.height(14.dp))
        }

        // Erasing is no longer "sign out and wipe" (that locked people out of their own
        // account): it is the explicit sheet that first checks the account has a way back.
        Surface(color = GlassCardTone, shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                Text(EraseCopy.TITLE, color = Color.White, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(6.dp))
                Text(EraseCopy.BODY, color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(10.dp))
                Button(onClick = { showErase = true },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF87171))) {
                    Icon(Icons.Filled.DeleteForever, null, tint = Color.Black); Spacer(Modifier.width(6.dp))
                    Text("Erase this device…", color = Color.Black)
                }
            }
        }
    }

    if (showReports) ReportsDialog { showReports = false }
    if (showErase) EraseDeviceDialog(onClose = { showErase = false }, onErased = { showErase = false; onSignOut() })

    confirmClearServer?.let { req ->
        AlertDialog(
            onDismissRequest = { confirmClearServer = null },
            confirmButton = {
                TextButton(onClick = {
                    confirmClearServer = null
                    // Only in the very skwod (and binding) it was opened in, and only as its owner.
                    if (!req.mayProceed(model.bound, model.isInstanceOwner)) return@TextButton
                    scope.launch {
                        withContext(Dispatchers.IO) {
                            for (sid in req.serverIds) {
                                if (!Asked.holds(req.asked, model.bound)) break
                                try { req.asked.client.clearServerMessages(sid) } catch (_: Exception) {}
                            }
                        }
                    }
                }) { Text("Clear all messages", color = Color(0xFFF87171)) }
            },
            dismissButton = { TextButton(onClick = { confirmClearServer = null }) { Text("Cancel") } },
            title = { Text("Clear all messages in ${req.skwodName}?") },
            text = { Text("Permanently deletes every message, story, and post across all channels, for everyone. Channels, members, and roles stay. This can't be undone.") }
        )
    }

    pendingDelete?.let { a ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            confirmButton = {
                TextButton(onClick = {
                    val target = a; pendingDelete = null
                    scope.launch { model.deleteAccount(target.userId); tick++ }
                }) { Text("Delete account", color = Color(0xFFF87171)) }
            },
            dismissButton = {
                Row {
                    TextButton(onClick = { pendingDeleteBan = a; pendingDelete = null }) { Text("Delete and ban…", color = Color(0xFFF87171)) }
                    TextButton(onClick = { pendingDelete = null }) { Text("Cancel") }
                }
            },
            title = { Text("Delete the account of ${model.contacts.shown(a.userId, a.username).label}?") },
            text = { Text("Wipes the account, devices, and memberships — the username is freed for a fresh sign-up.") }
        )
    }
    pendingDeleteBan?.let { a ->
        DeleteAndBanDialog(model.contacts.shown(a.userId, a.username).label, onDismiss = { pendingDeleteBan = null }) {
            pendingDeleteBan = null
            scope.launch { model.deleteAccountAndBan(a.userId); tick++ }
        }
    }
}
