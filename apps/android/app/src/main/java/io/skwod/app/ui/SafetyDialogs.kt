package io.skwod.app

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Who (and optionally which message) a block or a report is about. */
data class SafetyTarget(
    val userId: String, val name: String, val messageText: String? = null, val serverId: String? = null,
    /** A channel message: where it is, told to the skwod's owner only (sealed). */
    val channelId: String? = null, val messageId: String? = null,
)

/** "Block X?" — the same words wherever blocking is offered. */
@Composable
fun BlockDialog(model: AppModel, target: SafetyTarget, onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("Block ${target.name}?") },
        text = {
            Column {
                Text("You won't see their messages, posts, stories or reactions anywhere in this skwod, and they can't message you. They aren't told. You can unblock them from their name in the member list.")
                error?.let { Text(it, color = Color(0xFFFFA726), fontSize = 13.sp, modifier = Modifier.padding(top = 8.dp)) }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                scope.launch {
                    error = BlockList.setBlocked(model, target.userId, target.name, true)
                    if (error == null) onClose()
                }
            }, modifier = Modifier.testTag("block-confirm")) { Text("Block", color = Color(0xFFFF6B6B)) }
        },
        dismissButton = { TextButton(onClick = onClose) { Text("Cancel") } },
    )
}

/**
 * Report a person, or one message of theirs, to whoever runs the skwod — and say that it went.
 * The message's text is included only if the reporter switches that on; it then travels sealed
 * to the skwod's owner (the server's own report list never holds it).
 */
@Composable
fun ReportDialog(model: AppModel, target: SafetyTarget, onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    var category by remember { mutableStateOf(ReportCategories.all.first().first) }
    var note by remember { mutableStateOf("") }
    var include by remember { mutableStateOf(false) }
    var alsoBlock by remember { mutableStateOf(false) }
    var sending by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var sent by remember { mutableStateOf<uniffi.skwod_core.ReportReceipt?>(null) }

    val receipt = sent
    if (receipt != null) {
        AlertDialog(
            onDismissRequest = onClose,
            title = { Text("Report sent", modifier = Modifier.testTag("report-sent")) },
            text = {
                Column {
                    Text(if (receipt.sealedToOwner) "The skwod's owner will see it the next time they open Skwod. ${target.name} is not told."
                         else "It is in this skwod's report list. ${target.name} is not told.")
                    if (!receipt.sealedToOwner && include) {
                        Text("The message itself was not included: this skwod has no verified owner to encrypt it to.",
                            color = Color(0xFFFFA726), fontSize = 13.sp, modifier = Modifier.padding(top = 8.dp))
                    }
                }
            },
            confirmButton = { TextButton(onClick = onClose) { Text("Done") } },
        )
        return
    }
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("Report ${target.name}") },
        text = {
            Column {
                Text("The report goes to the person who runs this skwod. Your chats stay end-to-end encrypted: they see only what you choose to include here.",
                    fontSize = 13.sp, color = Color.White.copy(alpha = 0.7f))
                Spacer(Modifier.height(8.dp))
                for ((id, label) in ReportCategories.all) {
                    Row(Modifier.fillMaxWidth().clickable { category = id }, verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = category == id, onClick = { category = id })
                        Text(label)
                    }
                }
                OutlinedTextField(note, { note = it.take(2000) }, label = { Text("Add a note (optional)") },
                    modifier = Modifier.fillMaxWidth().testTag("report-note"), maxLines = 4)
                val text = target.messageText
                if (!text.isNullOrBlank()) {
                    Row(Modifier.fillMaxWidth().clickable { include = !include }.padding(top = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(include, { include = it }, modifier = Modifier.testTag("report-include-message"))
                        Column {
                            Text("Include this message")
                            Text("“${text.take(200)}”", fontSize = 12.sp, color = Color.White.copy(alpha = 0.55f), maxLines = 3)
                            Text("Sent encrypted to the skwod's owner only. Without it they see who you reported and why, not what was said.",
                                fontSize = 11.sp, color = Color.White.copy(alpha = 0.45f))
                        }
                    }
                }
                Row(Modifier.fillMaxWidth().clickable { alsoBlock = !alsoBlock }, verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(alsoBlock, { alsoBlock = it })
                    Text("Also block ${target.name}")
                }
                error?.let { Text(it, color = Color(0xFFFFA726), fontSize = 13.sp) }
            }
        },
        confirmButton = {
            TextButton(enabled = !sending, onClick = {
                val c = model.client ?: run { error = "Not connected — try again in a moment."; return@TextButton }
                sending = true; error = null
                scope.launch {
                    try {
                        val r = withContext(Dispatchers.IO) {
                            c.reportMessageAt(category, note.ifBlank { null }, if (include) target.messageText else null, target.userId, target.serverId,
                                target.channelId, target.messageId)
                        }
                        if (alsoBlock) BlockList.setBlocked(model, target.userId, target.name, true)
                        E2E.sawReport(r.reportId, r.sealedToOwner)
                        sent = r
                    } catch (_: Exception) {
                        error = "The report could not be sent — check your connection and try again."
                    }
                    sending = false
                }
            }, modifier = Modifier.testTag("report-send")) { Text(if (sending) "Sending…" else "Send report") }
        },
        dismissButton = { TextButton(onClick = onClose) { Text("Cancel") } },
    )
}

/** "Sending…" / "Not delivered — reason · Retry · Discard" under a message of mine (a failed send never reads as sent). */
@Composable
fun SendStateLine(state: SendState, onRetry: (String) -> Unit, onDiscard: (String) -> Unit) {
    when (state) {
        SendState.Sending -> Text("Sending…", color = Color.White.copy(alpha = 0.4f), fontSize = 10.sp, modifier = Modifier.testTag("send-state-sending"))
        is SendState.Failed -> Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.testTag("send-state-failed")) {
            Text("Not delivered — ${state.reason}", color = Color(0xFFFFA726), fontSize = 11.sp, modifier = Modifier.weight(1f, fill = false))
            Text("Retry", color = SkAccent, fontSize = 11.sp, modifier = Modifier.clickable { onRetry(state.localId) }.padding(horizontal = 8.dp, vertical = 6.dp))
            Text("Discard", color = Color.White.copy(alpha = 0.6f), fontSize = 11.sp, modifier = Modifier.clickable { onDiscard(state.localId) }.padding(horizontal = 4.dp, vertical = 6.dp))
        }
    }
}
