package io.skwod.app

import androidx.compose.foundation.layout.Column
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.NotificationsOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.size

/** The small mark a muted row carries. [key]: a conversation scope or [MuteList.SKWOD]. */
@Composable
fun MutedMark(model: AppModel, key: String) {
    model.muteRevision.intValue                      // redraw when a mute changes
    if (model.muteHolds(key)) {
        Icon(Icons.Filled.NotificationsOff, "Muted", tint = Color.White.copy(alpha = 0.4f), modifier = Modifier.size(16.dp))
    }
}

/** The mute entry of an existing long-press menu: opens the durations, or unmutes. */
@Composable
fun MuteMenuItem(model: AppModel, key: String, onPick: () -> Unit, onDone: () -> Unit) {
    model.muteRevision.intValue
    if (model.muteHolds(key)) {
        DropdownMenuItem(text = { Text("Unmute") }, onClick = { model.unmute(key); onDone() },
            leadingIcon = { Icon(Icons.Filled.Notifications, null) })
    } else {
        DropdownMenuItem(text = { Text(if (key == MuteList.SKWOD) "Mute this skwod…" else "Mute…") }, onClick = { onDone(); onPick() },
            leadingIcon = { Icon(Icons.Filled.NotificationsOff, null) })
    }
}

/** For how long? (Or, when it is muted already: unmute.) */
@Composable
fun MuteDialog(model: AppModel, key: String, onDismiss: () -> Unit) {
    val muted = model.muteHolds(key)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (muted) "Muted" else if (key == MuteList.SKWOD) "Mute this skwod" else "Mute") },
        text = {
            Column {
                if (muted) {
                    TextButton(onClick = { model.unmute(key); onDismiss() }) { Text("Unmute") }
                } else {
                    MuteList.Duration.values().forEach { d ->
                        TextButton(onClick = { model.mute(key, d); onDismiss() }) { Text(d.label) }
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
