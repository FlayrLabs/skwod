package io.skwod.app

import androidx.compose.foundation.layout.Column
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.launch

/**
 * The long-press menu of a server (rail tile, overview row). What it offers is [ServerMenu.items]:
 * mute, invite, and — for the owner — icon and permissions, then Delete server; for everyone
 * else, Leave server. Both end with a confirmation; Delete is spelled out.
 */
@Composable
fun ServerActionsMenu(
    expanded: Boolean, group: ServerGroup, onDismiss: () -> Unit,
    onInvite: () -> Unit, onIcon: () -> Unit, onPermissions: () -> Unit,
) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    // The core's PINNED owner decides ([ServerMenu.ownership]); the host's owner_id is only a
    // hint, used when nothing is pinned — and then every choice carries a warning.
    var pinnedOwner by remember(group.serverId) { mutableStateOf<String?>(null) }
    LaunchedEffect(group.serverId, expanded) { if (expanded) pinnedOwner = model.pinnedServerOwner(group.serverId) }
    val ownership = ServerMenu.ownership(pinnedOwner, model.session?.userId)
    val hostSaysOwner = ServerList.hostSaysOwner(model.serverOwners, group.serverId, model.session?.userId)
    val isOwner = ownership == ServerMenu.Ownership.OWNER
    var muting by remember { mutableStateOf(false) }
    var confirm by remember { mutableStateOf<ServerMenu.Item?>(null) }
    var busy by remember { mutableStateOf(false) }
    var problem by remember { mutableStateOf<String?>(null) }
    val keys = ServerMenu.muteKeys(group.channels.map { it.channelId })
    model.muteRevision.intValue
    val muted = keys.isNotEmpty() && keys.all { model.muteHolds(it) }

    DropdownMenu(expanded = expanded, onDismissRequest = onDismiss) {
        for (item in ServerMenu.items(ownership, hostSaysOwner)) when (item) {
            ServerMenu.Item.MUTE -> DropdownMenuItem(text = { Text(if (muted) "Unmute server" else "Mute server…") },
                onClick = { onDismiss(); if (muted) keys.forEach { model.unmute(it) } else muting = true },
                leadingIcon = { Icon(if (muted) Icons.Filled.Notifications else Icons.Filled.NotificationsOff, null) })
            ServerMenu.Item.INVITE -> DropdownMenuItem(text = { Text("Invite people") }, onClick = { onDismiss(); onInvite() },
                leadingIcon = { Icon(Icons.Filled.PersonAdd, null) })
            ServerMenu.Item.ICON -> DropdownMenuItem(text = { Text("Change server icon") }, onClick = { onDismiss(); onIcon() },
                leadingIcon = { Icon(Icons.Filled.Image, null) })
            ServerMenu.Item.PERMISSIONS -> DropdownMenuItem(text = { Text("Manage permissions") }, onClick = { onDismiss(); onPermissions() },
                leadingIcon = { Icon(Icons.Filled.Shield, null) })
            ServerMenu.Item.LEAVE -> DropdownMenuItem(text = { Text("Leave server", color = Color(0xFFF87171)) },
                onClick = { onDismiss(); confirm = item }, leadingIcon = { Icon(Icons.Filled.Logout, null, tint = Color(0xFFF87171)) })
            ServerMenu.Item.DELETE -> DropdownMenuItem(text = { Text("Delete server", color = Color(0xFFF87171)) },
                onClick = { onDismiss(); confirm = item }, leadingIcon = { Icon(Icons.Filled.DeleteForever, null, tint = Color(0xFFF87171)) })
        }
    }

    if (muting) AlertDialog(
        onDismissRequest = { muting = false },
        title = { Text("Mute ${group.name}") },
        text = {
            Column {
                MuteList.Duration.values().forEach { d ->
                    TextButton(onClick = { keys.forEach { model.mute(it, d) }; muting = false }) { Text(d.label) }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = { muting = false }) { Text("Cancel") } },
    )

    confirm?.let { what ->
        val deleting = what == ServerMenu.Item.DELETE
        AlertDialog(
            onDismissRequest = { if (!busy) { confirm = null; problem = null } },
            title = { Text(if (deleting) "Delete ${group.name} for everyone?" else "Leave ${group.name}?") },
            text = {
                Column {
                    Text(if (deleting) "Deletes the server, every channel and every message in it, for every member. This can't be undone."
                         else "You stop getting its messages, and this device forgets its keys. To come back you need a new invite.")
                    if (ServerMenu.warns(ownership)) Text("Skwod couldn't confirm who owns this server on this device — only the host says so. " +
                        (if (deleting) "If you are not its owner, the host will refuse." else "If you own it, the host will refuse; delete it instead."),
                        color = Color(0xFFFFA726))
                    problem?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                }
            },
            confirmButton = {
                TextButton(enabled = !busy, onClick = {
                    busy = true; problem = null
                    scope.launch {
                        val err = if (deleting) model.deleteServer(group.serverId) else model.leaveServer(group.serverId)
                        busy = false
                        if (err == null) confirm = null else problem = err
                    }
                }) { Text(if (busy) "…" else if (deleting) "Delete server" else "Leave", color = Color(0xFFF87171)) }
            },
            dismissButton = { TextButton(enabled = !busy, onClick = { confirm = null; problem = null }) { Text("Cancel") } },
        )
    }
}

/**
 * The long-press menu of a skwod (host) entry ([SkwodMenu.items]): a skwod that is not open only
 * opens (or logs in); the open one can be muted, its devices shown, signed out of, or removed
 * from this device — the same dialogs as in Profile.
 */
@Composable
fun SkwodActionsMenu(
    expanded: Boolean, w: Workspace, onDismiss: () -> Unit,
    onOpen: () -> Unit, onSignOut: () -> Unit, onRemoved: () -> Unit,
) {
    val model = AppModel.get(LocalContext.current)
    var muting by remember { mutableStateOf(false) }
    var devices by remember { mutableStateOf(false) }
    var erase by remember { mutableStateOf(false) }
    var renaming by remember { mutableStateOf(false) }
    DropdownMenu(expanded = expanded, onDismissRequest = onDismiss) {
        val items = SkwodMenu.items(isOpen = w.localId == model.current?.localId, signedOut = w.isSignedOut,
            duplicate = WorkspaceLabel.hasTwin(w, model.workspaces), instanceOwner = model.isInstanceOwner)
        for (item in items) when (item) {
            SkwodMenu.Item.OPEN -> DropdownMenuItem(text = { Text("Open ${w.displayName}") }, onClick = { onDismiss(); onOpen() },
                leadingIcon = { Icon(Icons.Filled.SwapHoriz, null) })
            SkwodMenu.Item.LOG_IN -> DropdownMenuItem(text = { Text("Log in again") }, onClick = { onDismiss(); onOpen() },
                leadingIcon = { Icon(Icons.Filled.Login, null) })
            SkwodMenu.Item.MUTE -> MuteMenuItem(model, MuteList.SKWOD, onPick = { muting = true }, onDone = onDismiss)
            SkwodMenu.Item.DEVICES -> DropdownMenuItem(text = { Text("Devices & security") }, onClick = { onDismiss(); devices = true },
                leadingIcon = { Icon(Icons.Filled.Devices, null) })
            SkwodMenu.Item.SIGN_OUT -> DropdownMenuItem(text = { Text("Sign out of this Skwod") }, onClick = { onDismiss(); onSignOut() },
                leadingIcon = { Icon(Icons.Filled.Logout, null) })
            SkwodMenu.Item.RENAME -> DropdownMenuItem(text = { Text("Rename on host") }, onClick = { onDismiss(); renaming = true },
                leadingIcon = { Icon(Icons.Filled.Edit, null) })
            SkwodMenu.Item.REMOVE_DUPLICATE -> DropdownMenuItem(text = { Text("Remove this duplicate") },
                onClick = { onDismiss(); model.removeDuplicate(w.localId) },
                leadingIcon = { Icon(Icons.Filled.ContentCopy, null) })
            SkwodMenu.Item.REMOVE_FROM_DEVICE -> DropdownMenuItem(text = { Text("Remove from this device", color = Color(0xFFF87171)) },
                onClick = { onDismiss(); erase = true }, leadingIcon = { Icon(Icons.Filled.PhonelinkErase, null, tint = Color(0xFFF87171)) })
        }
    }
    if (muting) MuteDialog(model, MuteList.SKWOD) { muting = false }
    if (devices) DevicesDialog { devices = false }
    if (erase) EraseDeviceDialog(onClose = { erase = false }, onErased = { erase = false; onRemoved() })
    if (renaming) RenameOnHostDialog(initial = w.instanceName ?: "", onClose = { renaming = false })
}

/** The instance owner names the skwod on its host; every member sees it beside the host key. */
@Composable
private fun RenameOnHostDialog(initial: String, onClose: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf(initial) }
    var busy by remember { mutableStateOf(false) }
    var problem by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        title = { Text("Rename on host") },
        text = {
            Column {
                Text("Every member sees this name, with the host key beside it. Letters, digits, spaces, - _ ' & and emoji; up to ${SkwodName.MAX}. Leave it empty to clear it.")
                OutlinedTextField(value = text, onValueChange = { text = it; problem = null }, singleLine = true,
                    label = { Text("Skwod name") }, isError = problem != null,
                    supportingText = problem?.let { p -> { Text(p) } })
            }
        },
        confirmButton = {
            TextButton(enabled = !busy, onClick = {
                busy = true
                scope.launch {
                    val failed = model.setInstanceName(text)
                    busy = false
                    if (failed == null) onClose() else problem = failed
                }
            }) { Text("Rename") }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onClose) { Text("Cancel") } },
    )
}
