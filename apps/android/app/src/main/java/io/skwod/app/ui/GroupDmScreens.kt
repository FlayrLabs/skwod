package io.skwod.app

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/**
 * Pick the people of a group: the DM contacts and the accepted members of the user's servers,
 * never anyone this account blocked. [fixed] are already in (adding to an existing group); the
 * result is always a group made of exactly the people shown ticked — the user's own choice,
 * which is what every message of the group is then sealed to.
 */
@Composable
fun GroupPickerDialog(title: String, confirm: String, fixed: List<String>, onCancel: () -> Unit, onPicked: (GroupConversation) -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    val me = model.session?.userId
    val picked = remember { mutableStateListOf<String>() }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirming by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) { model.refreshRoster() }
    val blocked = BlockList.ids
    val candidates = remember(model.chat.revision, model.contacts.roster, blocked) {
        (model.chat.dms.filter { it.bound && !it.isSplit }.map { it.peerUserId } + model.contacts.roster.keys)
            .distinct().filter { it != me && it !in blocked && it !in fixed && !model.isBlockedUser(it) }
    }
    val total = fixed.size + picked.size

    fun start() {
        if (busy) return
        busy = true; error = null
        scope.launch {
            try { onPicked(model.groups.open(fixed + picked)) }
            catch (e: Exception) { error = coreErrorDetail(e) ?: e.message?.takeIf { e is IllegalStateException } ?: "Couldn't start the group — check your connection." }
            busy = false
        }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onCancel() },
        confirmButton = {
            TextButton(enabled = !busy && picked.isNotEmpty() && GroupRules.canStart(total), onClick = {
                // Adding people to a group that exists cannot change it: say what will happen.
                if (fixed.isNotEmpty()) confirming = true else start()
            }) { Text(if (busy) "…" else confirm) }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onCancel) { Text("Cancel") } },
        title = { Text(title) },
        text = {
            Column {
                Text(GroupRules.counter(total), color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.labelMedium)
                Spacer(Modifier.height(6.dp))
                if (candidates.isEmpty()) {
                    Text("Nobody to add yet. Start a chat with someone, or join a server, and they will be listed here.",
                        color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.bodySmall)
                } else LazyColumn(Modifier.heightIn(max = 340.dp)) {
                    items(candidates, key = { it }) { id ->
                        val shown = model.groups.shown(id)
                        val on = id in picked
                        Row(Modifier.fillMaxWidth().clickable(enabled = on || total < GroupRules.MAX_OTHERS) { if (on) picked.remove(id) else picked.add(id) }
                            .padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(on, onCheckedChange = null, enabled = on || total < GroupRules.MAX_OTHERS)
                            Spacer(Modifier.width(10.dp))
                            Text(shown.name, color = if (shown.strong) Color(0xFFF87171) else Color.White, maxLines = 1)
                            NameTrustMark(shown)
                        }
                    }
                }
                error?.let { Text(it, color = Color(0xFFFFA726), style = MaterialTheme.typography.labelSmall) }
            }
        }
    )

    if (confirming) NewGroupConfirm((fixed + picked).map { model.groups.shown(it).label }, onCancel = { confirming = false }) { confirming = false; start() }
}

/** "This starts a new group with …" — the one honest thing to say about changing a group's people. */
@Composable
private fun NewGroupConfirm(names: List<String>, onCancel: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        confirmButton = { TextButton(onClick = onConfirm) { Text("Start new group") } },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
        title = { Text("Start a new group?") },
        text = { Text(GroupRules.newGroupConfirm(names)) }
    )
}

/**
 * Header → "People": who is in the group, how far each name is trusted, and each person's safety
 * number. Adding or removing someone starts a NEW group with the changed set and opens it — the
 * server has no way to change a group's members, and this screen does not pretend otherwise.
 */
@Composable
fun GroupPeopleDialog(group: GroupConversation, onClose: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var verify by remember { mutableStateOf<String?>(null) }
    var adding by remember { mutableStateOf(false) }
    var removing by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    fun open(g: GroupConversation) { onClose(); model.chat.homeMode = false; model.chat.selection = SidebarItem.Group(g) }
    // Read live: the flag is set when the server's listing is found to differ.
    val revision = model.groups.revision.intValue
    val disagrees = remember(revision, group.conversationId) { model.groups.find(group.conversationId)?.serverDisagrees == true } || group.serverDisagrees

    verify?.let { id ->
        SafetyNumberDialog(model.groups.shown(id, group).name, id, onChanged = {}, onClose = { verify = null })
        return
    }
    if (adding) {
        GroupPickerDialog(title = "Add people…", confirm = "Add", fixed = group.others, onCancel = { adding = false }, onPicked = { adding = false; open(it) })
        return
    }

    AlertDialog(
        onDismissRequest = onClose,
        confirmButton = { TextButton(onClick = onClose) { Text("Done") } },
        dismissButton = {
            TextButton(enabled = group.others.size < GroupRules.MAX_OTHERS, onClick = { adding = true }) { Text("Add people…") }
        },
        title = { Text("People") },
        text = {
            Column {
                Text(GroupRules.SEALED_LINE, color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.bodySmall)
                if (disagrees) {
                    Spacer(Modifier.height(6.dp))
                    Row {
                        Icon(Icons.Filled.GppMaybe, null, tint = Color(0xFFFFA726), modifier = Modifier.size(16.dp)); Spacer(Modifier.width(6.dp))
                        Text(GroupRules.SERVER_DISAGREES, color = Color(0xFFFFA726), style = MaterialTheme.typography.labelSmall)
                    }
                }
                Spacer(Modifier.height(8.dp))
                LazyColumn(Modifier.heightIn(max = 360.dp)) {
                    items(group.others, key = { it }) { id ->
                        val shown = model.groups.shown(id, group)
                        Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                AvatarImage(AvatarStore.userKey(id), shown.name, size = 30); Spacer(Modifier.width(10.dp))
                                Text(shown.name, color = if (shown.strong) Color(0xFFF87171) else Color.White, maxLines = 1)
                                NameTrustMark(shown)
                            }
                            shown.warning?.let { (text, strong) ->
                                Text(text, color = if (strong) Color(0xFFF87171) else Color(0xFFFFA726), style = MaterialTheme.typography.labelSmall)
                            }
                            Row {
                                TextButton(onClick = { verify = id }) { Text("View safety number", color = SkAccent) }
                                // Removing someone needs a group to be left over (at least two others).
                                if (GroupRules.changed(group.others, removed = id) != null) {
                                    TextButton(onClick = { removing = id }) { Text("Remove ${shown.name}…", color = Color(0xFFF87171)) }
                                }
                            }
                        }
                        HorizontalDivider(color = Color.White.copy(alpha = 0.06f))
                    }
                }
                error?.let { Text(it, color = Color(0xFFFFA726), style = MaterialTheme.typography.labelSmall) }
            }
        }
    )

    removing?.let { id ->
        val next = GroupRules.changed(group.others, removed = id) ?: run { removing = null; return@let }
        NewGroupConfirm(next.map { model.groups.shown(it).label }, onCancel = { removing = null }) {
            removing = null
            scope.launch {
                try { open(model.groups.open(next)) }
                catch (e: Exception) { error = coreErrorDetail(e) ?: "Couldn't start the group — check your connection." }
            }
        }
    }
}

/**
 * A group this device has not accepted: who is in it — as THIS device names them — and the
 * choice. Joining fixes the member set this device seals to: exactly the people shown here.
 */
@Composable
fun GroupInviteDialog(invitation: GroupConversation, onClose: () -> Unit, onJoined: (GroupConversation) -> Unit) {
    val shownFirst = invitation
    val model = AppModel.get(LocalContext.current)
    // What is ON SCREEN — the only member set "Join group" can accept. If the invitation
    // changed meanwhile nothing is joined: the new one is shown, with a line saying so.
    @Suppress("NAME_SHADOWING") var invitation by remember { mutableStateOf(shownFirst) }
    var changed by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onClose,
        confirmButton = {
            TextButton(onClick = {
                when (val r = model.groups.join(invitation)) {
                    is ConversationStore.Joined.Done -> onJoined(r.group)
                    is ConversationStore.Joined.Changed -> { invitation = r.now; changed = true }
                    is ConversationStore.Joined.Refused -> onClose()
                }
            }) { Text("Join group") }
        },
        dismissButton = {
            Row {
                TextButton(onClick = { model.groups.decline(invitation); onClose() }) { Text("Ignore this group", color = Color(0xFFF87171)) }
                TextButton(onClick = onClose) { Text("Not now") }
            }
        },
        title = { Text(if (invitation.needsReview) GroupRules.REVIEW_TITLE else GroupRules.JOIN_TITLE) },
        text = {
            Column {
                Text(if (invitation.needsReview) GroupRules.REVIEW_BODY else GroupRules.JOIN_BODY, color = Color.White.copy(alpha = 0.7f), style = MaterialTheme.typography.bodySmall)
                if (changed) Text(GroupRules.INVITATION_CHANGED, color = Color(0xFFFFA726), style = MaterialTheme.typography.labelSmall)
                Spacer(Modifier.height(10.dp))
                LazyColumn(Modifier.heightIn(max = 320.dp)) {
                    items(invitation.others, key = { it }) { id ->
                        val shown = model.groups.shown(id, invitation)
                        Column(Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                AvatarImage(AvatarStore.userKey(id), shown.name, size = 28); Spacer(Modifier.width(10.dp))
                                Text(shown.name, color = if (shown.strong) Color(0xFFF87171) else Color.White, maxLines = 1)
                                NameTrustMark(shown)
                            }
                            shown.warning?.let { (text, strong) ->
                                Text(text, color = if (strong) Color(0xFFF87171) else Color(0xFFFFA726), style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }
                }
            }
        }
    )
}

/**
 * What the user has to be TOLD about their conversation lists, where the lists are: they cannot
 * be read (try again); a saved list was lost and server-listed conversations are held back
 * until the user says so; and the groups they ignored.
 */
@Composable
fun ConversationNotices() {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var showIgnored by remember { mutableStateOf(false) }

    @Composable
    fun row(text: String, action: String, run: () -> Unit) {
        Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Text(text, color = Color(0xFFFFA726), style = MaterialTheme.typography.labelMedium)
            TextButton(onClick = run, contentPadding = PaddingValues(0.dp)) { Text(action, color = SkAccent) }
        }
    }
    if (model.groups.loadFailures.intValue >= 2 && model.bound?.cacheOpen == true) {
        row(GroupRules.LISTS_UNREADABLE, "Try again") { scope.launch { model.groups.retryLoad() } }
    }
    if (model.groups.reviewPending.value) {
        row(GroupRules.REVIEW_PENDING, "I’ve seen this — continue") { scope.launch { model.groups.clearReview() } }
    }
    if (model.groups.ignored.isNotEmpty()) {
        TextButton(onClick = { showIgnored = true }, contentPadding = PaddingValues(0.dp)) {
            Text("${GroupRules.IGNORED_TITLE} (${model.groups.ignored.size})", color = Color.White.copy(alpha = 0.55f))
        }
    }
    if (showIgnored) {
        AlertDialog(
            onDismissRequest = { showIgnored = false },
            confirmButton = { TextButton(onClick = { showIgnored = false }) { Text("Done") } },
            title = { Text(GroupRules.IGNORED_TITLE) },
            text = {
                Column {
                    Text(GroupRules.IGNORED_BODY, color = Color.White.copy(alpha = 0.7f), style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    // Only the conversation ids are kept of an ignored group, so that is what can be shown.
                    for (id in model.groups.ignored.toList()) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("Group ${id.take(8)}", color = Color.White, modifier = Modifier.weight(1f), maxLines = 1)
                            TextButton(onClick = { scope.launch { model.groups.unignore(id); if (model.groups.ignored.isEmpty()) showIgnored = false } }) {
                                Text("Stop ignoring", color = SkAccent)
                            }
                        }
                    }
                }
            }
        )
    }
}
