package io.skwod.app

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import kotlinx.coroutines.launch
import uniffi.skwod_core.AbuseReport

/**
 * The reports inbox of the skwod's owner. A report's note and quoted message were sealed to this
 * account's devices; the server's own queue holds who / whom / category and no text. What the
 * reporter quotes is their CLAIM — the card says whether this device's own copy of the channel
 * backs it — and every action asks first.
 */
@Composable
fun ReportsDialog(onClose: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    val reports = model.reports.list
    var message by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { model.syncDmsNow(); model.reports.refresh() }

    Dialog(onDismissRequest = onClose) {
        Surface(color = GlassDialogTone, shape = RoundedCornerShape(20.dp)) {
            Column(Modifier.padding(20.dp).verticalScroll(rememberScrollState())) {
                Text("Reports", color = Color.White, style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(8.dp))
                if (reports.isEmpty()) Text("No reports. When someone reports a person or a message in this skwod, it shows up here.",
                    color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.bodySmall)
                reports.forEach { r -> key(r.reportId) { ReportCard(r, onError = { message = it }) } }
                if (message.isNotEmpty()) Text(message, color = Color(0xFFFFA726), style = MaterialTheme.typography.labelSmall)
                TextButton(onClick = onClose, modifier = Modifier.align(Alignment.End)) { Text("Done") }
            }
        }
    }
}

@Composable
private fun ReportCard(r: AbuseReport, onError: (String) -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var resolution by remember { mutableStateOf<ReportRules.Resolution>(ReportRules.Resolution.Unresolved) }
    /** An action waiting for its confirmation: what, and (kick / ban) the server and person it names. */
    var confirm by remember { mutableStateOf<Pending?>(null) }
    var picking by remember { mutableStateOf<Boolean?>(null) }       // null = no; true = ban; false = kick
    var busy by remember { mutableStateOf(false) }
    val outbox = Outbox.revision.intValue
    LaunchedEffect(r.reportId, outbox, model.chat.revision) { resolution = model.reports.resolve(r) }

    // Names go through the contact book: a report must not be able to borrow a trusted name.
    fun person(id: String): String = model.contacts.shown(id, model.contacts.claimedName(id)).label
    fun serverName(id: String): String? = model.chat.serverGroups().firstOrNull { it.serverId == id }?.name
    val reporter = person(r.reporterUserId)
    val claimedSubject = r.subjectUserId?.takeIf { it.isNotEmpty() }?.let(::person)
    val target = resolution as? ReportRules.Resolution.Target
    val match = model.reports.match(r, target)

    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp).background(Color.White.copy(alpha = 0.05f), RoundedCornerShape(14.dp)).padding(12.dp)) {
        Text(ReportRules.headline(reporter, claimedSubject), color = Color.White, fontWeight = FontWeight.SemiBold)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(r.category, color = Color.Black, style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.background(Color(0xFFFFA726), RoundedCornerShape(50)).padding(horizontal = 8.dp, vertical = 2.dp))
            Spacer(Modifier.width(8.dp))
            Text(AccountDates.ago(r.receivedAt, System.currentTimeMillis()), color = Color.White.copy(alpha = 0.45f), style = MaterialTheme.typography.labelSmall)
        }
        r.note?.takeIf { it.isNotBlank() }?.let { note ->
            Spacer(Modifier.height(8.dp))
            Text("Their note", color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
            Text(note, color = Color.White, style = MaterialTheme.typography.bodySmall)
        }
        // What THIS device holds: the message itself, who really wrote it, where it really is.
        // Every action below acts on this — never on the person or server the report names.
        if (target != null) {
            Spacer(Modifier.height(8.dp))
            Text("The message on this device", color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
            Quote(ChatTags.parse(target.text).let { p -> p.text.ifBlank { if (p.attachment != null) "(an attachment)" else if (p.music != null) "(a song)" else "(no text)" } })
            Text("By ${if (target.authorIsMe) "you" else target.authorId?.let(::person) ?: "someone this device can't name"} · in ${serverName(target.serverId) ?: "a server"}",
                color = Color.White.copy(alpha = 0.7f), style = MaterialTheme.typography.labelSmall)
            target.warnings.forEach { Text(it, color = Color(0xFFF87171), style = MaterialTheme.typography.labelSmall) }
        }
        r.excerpt?.takeIf { it.isNotBlank() }?.let { excerpt ->
            Spacer(Modifier.height(8.dp))
            Text("Quoted message", color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
            Quote(excerpt)
            Text(match.caption, style = MaterialTheme.typography.labelSmall, color = when (match) {
                ReportRules.Match.MATCHES -> Color(0xFF4ADE80)
                ReportRules.Match.DIFFERS -> Color(0xFFFFA726)
                ReportRules.Match.UNKNOWN -> Color.White.copy(alpha = 0.5f)
            })
        }
        Spacer(Modifier.height(6.dp))
        @OptIn(ExperimentalLayoutApi::class)
        FlowRow {
            if (target != null) {
                // Offered only while the report agrees with what this device resolved.
                if (target.canRemove) TextButton(enabled = !busy, onClick = { confirm = Pending("remove") }) { Text("Remove message", color = Color(0xFFF87171)) }
                if (target.canModerate) {
                    val name = person(target.authorId!!)
                    val server = serverName(target.serverId) ?: "this server"
                    TextButton(enabled = !busy, onClick = { confirm = Pending("kick", name = name, server = server) }) { Text("Kick $name", color = Color(0xFFFACC15)) }
                    TextButton(enabled = !busy, onClick = { confirm = Pending("ban", name = name, server = server) }) { Text("Ban $name", color = Color(0xFFFB923C)) }
                }
            } else {
                // Nothing on this device backs the report, so nothing is prefilled from it: the
                // owner says which server and which person, and confirms both by name.
                TextButton(enabled = !busy, onClick = { picking = false }) { Text("Kick someone…", color = Color(0xFFFACC15)) }
                TextButton(enabled = !busy, onClick = { picking = true }) { Text("Ban someone…", color = Color(0xFFFB923C)) }
            }
            TextButton(enabled = !busy, onClick = { confirm = Pending("dismiss") }) { Text("Dismiss") }
        }
    }

    picking?.let { ban ->
        ModerationPicker(ban, hint = ReportRules.hint(claimedSubject, r.serverId?.takeIf { it.isNotEmpty() }?.let { serverName(it) ?: "a server this device doesn't know" }),
            onCancel = { picking = null },
            onPicked = { serverId, server, userId, name -> picking = null; confirm = Pending(if (ban) "ban" else "kick", name, server, serverId to userId) })
    }

    confirm?.let { pending ->
        val (title, body, label) = when (pending.action) {
            "remove" -> Triple("Remove this message?", "Deletes the message from the channel for everyone. This can't be undone.", "Remove message")
            "kick" -> Triple(ReportRules.confirmTitle(false, pending.name, pending.server), "Removes them from the server. Their account survives and they can rejoin with an invite.", "Kick")
            "ban" -> Triple(ReportRules.confirmTitle(true, pending.name, pending.server), "Removes them AND blocks every invite from readmitting them until you unban. Their account survives.", "Ban")
            else -> Triple("Dismiss this report?", "It is removed from this device's list. Nobody is told.", "Dismiss")
        }
        AlertDialog(
            onDismissRequest = { confirm = null },
            confirmButton = {
                TextButton(onClick = {
                    confirm = null; busy = true
                    scope.launch {
                        when (pending.action) {
                            "remove" -> model.reports.remove(r)
                            "kick" -> model.reports.moderate(r, ban = false, manual = pending.manual)
                            "ban" -> model.reports.moderate(r, ban = true, manual = pending.manual)
                            else -> model.reports.dismiss(r)
                        }?.let(onError)
                        resolution = model.reports.resolve(r)
                        busy = false
                    }
                }) { Text(label, color = if (pending.action == "dismiss") SkAccent else Color(0xFFF87171)) }
            },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text("Cancel") } },
            title = { Text(title) }, text = { Text(body) }
        )
    }
}

/** An action awaiting confirmation. [manual] = the (server id, user id) the owner picked by hand. */
private data class Pending(val action: String, val name: String = "", val server: String = "", val manual: Pair<String, String>? = null)

@Composable
private fun Quote(text: String) {
    Row(Modifier.padding(top = 2.dp).height(IntrinsicSize.Min)) {
        Box(Modifier.width(3.dp).fillMaxHeight().background(Color.White.copy(alpha = 0.3f)))
        Spacer(Modifier.width(8.dp))
        Text(text.take(600), color = Color.White.copy(alpha = 0.85f), fontStyle = FontStyle.Italic, style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * The explicit step for a report this device cannot back with a message: pick a server this
 * account is in, then a person from THAT server's member list. The report's own claim is shown
 * as a hint and selects nothing.
 */
@Composable
private fun ModerationPicker(ban: Boolean, hint: String?, onCancel: () -> Unit, onPicked: (serverId: String, server: String, userId: String, name: String) -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val me = model.session?.userId
    val servers = model.chat.serverGroups().filter { it.serverId.isNotEmpty() && it.serverId != "demo" }
    var server by remember { mutableStateOf<ServerGroup?>(null) }
    var members by remember { mutableStateOf<List<uniffi.skwod_core.MemberInfo>?>(null) }
    LaunchedEffect(server?.serverId) {
        members = null
        val sid = server?.serverId ?: return@LaunchedEffect
        members = try { kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) { model.client?.listMembers(sid) } } catch (_: Exception) { emptyList() } ?: emptyList()
    }
    AlertDialog(
        onDismissRequest = onCancel,
        confirmButton = {},
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
        title = { Text(if (ban) "Ban someone" else "Kick someone") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text("This report doesn't point at a message on this device, so Skwod can't tell who it is about. Choose the server and the person yourself.",
                    style = MaterialTheme.typography.bodySmall)
                hint?.let { Spacer(Modifier.height(6.dp)); Text(it, color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall) }
                Spacer(Modifier.height(10.dp))
                val picked = server
                if (picked == null) {
                    Text("Server", color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
                    if (servers.isEmpty()) Text("You aren't in any server on this Skwod.", style = MaterialTheme.typography.bodySmall)
                    servers.forEach { g -> TextButton(onClick = { server = g }) { Text(g.name) } }
                } else {
                    TextButton(onClick = { server = null }) { Text("‹ ${picked.name}") }
                    Text("Person", color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
                    val list = members
                    if (list == null) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = SkAccent)
                    else list.filter { it.userId != me }.forEach { m ->
                        val shown = model.contacts.shown(m.userId, m.username)
                        TextButton(onClick = { onPicked(picked.serverId, picked.name, m.userId, shown.label) }) {
                            Text(shown.label, color = if (shown.strong) Color(0xFFF87171) else Color.White)
                        }
                    }
                }
            }
        }
    )
}

/** A "Reports" menu row with its count, for wherever server management lives. */
@Composable
fun ReportsBadge(count: Int) {
    if (count > 0) Badge(containerColor = Color(0xFFFFA726), contentColor = Color.Black) { Text(ReportRules.badge(count)) }
}
