package io.skwod.app

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.HourglassTop
import androidx.compose.material.icons.filled.HowToReg
import androidx.compose.material.icons.filled.NoEncryption
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withLink
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Flag
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Reply
import androidx.compose.material.icons.filled.Forward
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.composed
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.onLongClick
import androidx.compose.ui.unit.sp

/** One reaction group on a message (emoji, count, whether I added it). Matches iOS ReactionPill. */
data class ReactionPill(val emoji: String, val count: Int, val mine: Boolean)

/** The default quick-react set, shown in the long-press menu. */
val quickReactions = listOf("👍", "❤️", "😂", "🎉", "😮", "😢", "🔥", "🙏")

/**
 * A message row (avatar + author + time, then the body) — the shared rendering used by
 * channel and DM chat, matching the iOS `MessageRow`. Consecutive messages from the same author are
 * "grouped": only the first shows the header, the rest just indent. Long-press opens the context menu
 * (react / copy / reply / forward / edit / delete). `actions` nil = plain row (DMs / demo).
 */
data class MessageActions(
    val onReact: (String) -> Unit,
    val onReply: () -> Unit,
    val onEdit: () -> Unit,
    /** Null where forwarding is not offered (direct messages). */
    val onForward: (() -> Unit)?,
    val onDelete: () -> Unit,
    /** Someone else's message: report it (optionally with what it says) / block its author. */
    val onReport: (() -> Unit)? = null,
    val onBlock: (() -> Unit)? = null,
    /** A message of mine that has not gone out: try again / give up. */
    val onRetry: ((String) -> Unit)? = null,
    val onDiscard: ((String) -> Unit)? = null,
)

/**
 * A persistent security / membership event shown in the conversation (not a message): centred,
 * quiet for routine events ("Sam joined — let in by you") and amber for ones that need a
 * decision, with an optional action ("Review", "View safety number").
 */
@Composable
fun SystemRow(row: SystemRowInfo, createdAt: Long = 0, onAction: (() -> Unit)? = null) {
    val amber = Color(0xFFFFA726)
    val tint = if (row.warning) amber else Color.White.copy(alpha = 0.55f)
    val icon = when (row.icon) {
        SystemRowIcon.JOINED -> Icons.Filled.HowToReg
        SystemRowIcon.DEVICE -> Icons.Filled.Devices
        SystemRowIcon.HELD -> Icons.Filled.HourglassTop
        SystemRowIcon.ALERT -> Icons.Filled.GppMaybe
        SystemRowIcon.SHIELD -> Icons.Filled.Shield
    }
    Box(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp), contentAlignment = Alignment.Center) {
        Row(
            Modifier.widthIn(max = 520.dp)
                .background(if (row.warning) amber.copy(alpha = 0.10f) else Color.White.copy(alpha = 0.04f), RoundedCornerShape(12.dp))
                .border(1.dp, if (row.warning) amber.copy(alpha = 0.35f) else Color.White.copy(alpha = 0.07f), RoundedCornerShape(12.dp))
                .padding(horizontal = 12.dp, vertical = 8.dp),
        ) {
            Icon(icon, null, tint = tint, modifier = Modifier.padding(top = 2.dp).size(15.dp))
            Spacer(Modifier.width(8.dp))
            Column {
                Text(row.text, color = Color.White.copy(alpha = if (row.warning) 0.9f else 0.6f), fontSize = 12.5.sp)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (createdAt > 0) {
                        Text(java.text.SimpleDateFormat("MMM d, h:mm a", java.util.Locale.getDefault()).format(java.util.Date(createdAt)),
                            color = Color.White.copy(alpha = 0.3f), fontSize = 10.sp)
                        Spacer(Modifier.width(10.dp))
                    }
                    if (row.actionLabel != null && onAction != null) {
                        Text(row.actionLabel, color = if (row.warning) amber else SkAccent, fontSize = 11.sp, fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.clickable(onClick = onAction).padding(vertical = 6.dp, horizontal = 2.dp))
                    }
                }
            }
        }
    }
}

/**
 * The stand-in for a message this device could not decrypt: muted, italic, a lock with a slash —
 * a system-style row, not a bubble. There is nothing to react to, reply to or copy, so it has no
 * menu. The view only redraws; the core replaces or removes the row when the resend arrives.
 */
@Composable
fun UndecryptableRowView(text: String, createdAt: Long = 0) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp).padding(start = 44.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(Icons.Filled.NoEncryption, null, tint = Color.White.copy(alpha = 0.4f), modifier = Modifier.size(15.dp))
        Spacer(Modifier.width(8.dp))
        Text(text, color = Color.White.copy(alpha = 0.45f), fontStyle = FontStyle.Italic, fontSize = 13.sp, modifier = Modifier.weight(1f, fill = false))
        if (createdAt > 0) {
            Spacer(Modifier.width(8.dp))
            Text(shortTime(createdAt), color = Color.White.copy(alpha = 0.3f), fontSize = 10.sp)
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun MessageRow(
    author: String, body: String, mine: Boolean, createdAt: Long, grouped: Boolean, authorId: String? = null,
    isEdited: Boolean = false, isDeleted: Boolean = false, replyPreview: String? = null,
    reactions: List<ReactionPill> = emptyList(), actions: MessageActions? = null,
    /** How far the author's name is trusted ([ContactBook.shown]); null for my own rows. */
    nameTrust: ContactTrust.Shown? = null,
    /** Mine and not delivered yet ([Outbox]): "Sending…" or "Not sent" with Retry / Discard. */
    sendState: SendState? = null,
    /** It mentions me (or is an honoured @everyone, or replies to me): the row is highlighted. */
    mentionsMe: Boolean = false,
    /** How a mention's account is named here (trust-labelled); see [LocalMentionName]. */
    mentionName: ((String, String) -> String)? = null,
) {
    val clipboard = LocalClipboardManager.current
    val parsed = remember(body) { ChatTags.parse(body) }
    var menu by remember { mutableStateOf(false) }
    var picker by remember { mutableStateOf(false) }
    Column(
        Modifier.fillMaxWidth()
            .then(if (mentionsMe) Modifier.background(Color(0xFFFFA726).copy(alpha = 0.08f)) else Modifier)
            .messageLongPress(enabled = !isDeleted && actions != null) { menu = true }
            .semantics { if (!isDeleted && actions != null) onLongClick("Message actions") { menu = true; true } }
            .padding(horizontal = 16.dp).padding(top = if (grouped) 1.dp else 10.dp, bottom = 1.dp)
    ) {
        replyPreview?.let {
            Text("↩ $it", color = Color.White.copy(alpha = 0.45f), fontSize = 12.sp,
                modifier = Modifier.padding(start = 44.dp))
        }
        if (!grouped) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                AvatarImage(authorId?.let { AvatarStore.userKey(it) }, if (mine) "You" else author, size = 34)
                Spacer(Modifier.width(10.dp))
                Text(if (mine) "You" else author, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                if (!mine && nameTrust != null) NameTrustMark(nameTrust)
                Spacer(Modifier.width(8.dp))
                Text(shortTime(createdAt), color = Color.White.copy(alpha = 0.4f), fontSize = 11.sp)
            }
        }
        // Body indented to line up under the header text (avatar 34 + gap 10).
        Column(Modifier.padding(start = 44.dp, top = if (grouped) 0.dp else 2.dp)) {
            if (isDeleted) {
                Text("message deleted", color = Color.White.copy(alpha = 0.35f), fontStyle = FontStyle.Italic, fontSize = 14.sp)
            } else {
                androidx.compose.runtime.CompositionLocalProvider(LocalMentionName provides (mentionName ?: LocalMentionName.current)) { MessageBody(body) }
                if (isEdited) Text("(edited)", color = Color.White.copy(alpha = 0.3f), fontSize = 10.sp)
                if (sendState != null) SendStateLine(sendState, onRetry = { actions?.onRetry?.invoke(it) }, onDiscard = { actions?.onDiscard?.invoke(it) })
            }
            if (reactions.isNotEmpty() && actions != null) {
                Row(Modifier.padding(top = 3.dp), horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                    for (r in reactions) {
                        val bg = if (r.mine) SkAccent.copy(alpha = 0.28f) else Color.White.copy(alpha = 0.08f)
                        Row(
                            Modifier.background(bg, CircleShape)
                                .border(1.dp, if (r.mine) SkAccent.copy(alpha = 0.6f) else Color.White.copy(alpha = 0.12f), CircleShape)
                                .combinedClickable(onClick = { actions.onReact(r.emoji) }, onLongClick = {})
                                .padding(horizontal = 8.dp, vertical = 3.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(r.emoji, fontSize = 12.sp)
                            if (r.count > 1) Text(" ${r.count}", color = Color.White.copy(alpha = 0.7f), fontSize = 11.sp)
                        }
                    }
                }
            }
        }
        if (actions != null && picker) EmojiPickerSheet(onPick = { actions.onReact(it) }, onDismiss = { picker = false })
        if (actions != null) {
            DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                Row(Modifier.padding(horizontal = 8.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    for (e in quickReactions) {
                        Text(e, fontSize = 20.sp, modifier = Modifier
                            .combinedClickable(onClick = { menu = false; actions.onReact(e) }, onLongClick = {})
                            .padding(4.dp))
                    }
                    // Any other emoji: the full picker (build 49).
                    Text("＋", fontSize = 20.sp, color = Color.White.copy(alpha = 0.8f), modifier = Modifier
                        .combinedClickable(onClick = { menu = false; picker = true }, onLongClick = {})
                        .padding(4.dp))
                }
                if (parsed.text.isNotBlank()) {
                    DropdownMenuItem(text = { Text("Copy Text") }, onClick = {
                        menu = false; clipboard.setText(AnnotatedString(parsed.text))
                    }, leadingIcon = { Icon(Icons.Filled.ContentCopy, null) })
                }
                DropdownMenuItem(text = { Text("Reply") }, onClick = { menu = false; actions.onReply() },
                    leadingIcon = { Icon(Icons.Filled.Reply, null) })
                actions.onForward?.let { forward ->
                    DropdownMenuItem(text = { Text("Forward") }, onClick = { menu = false; forward() },
                        leadingIcon = { Icon(Icons.Filled.Forward, null) })
                }
                if (!mine) {
                    actions.onReport?.let { report ->
                        DropdownMenuItem(text = { Text("Report…") }, onClick = { menu = false; report() },
                            leadingIcon = { Icon(Icons.Filled.Flag, null) })
                    }
                    actions.onBlock?.let { block ->
                        DropdownMenuItem(text = { Text("Block $author…") }, onClick = { menu = false; block() },
                            leadingIcon = { Icon(Icons.Filled.Block, null) })
                    }
                }
                if (mine) {
                    if (parsed.attachment == null && parsed.music == null) {
                        DropdownMenuItem(text = { Text("Edit") }, onClick = { menu = false; actions.onEdit() },
                            leadingIcon = { Icon(Icons.Filled.Edit, null) })
                    }
                    DropdownMenuItem(text = { Text("Delete") }, onClick = { menu = false; actions.onDelete() },
                        leadingIcon = { Icon(Icons.Filled.Delete, null) })
                }
            }
        }
    }
}

/**
 * Long-press anywhere on a message row opens its menu — also over a picture, a file card or a
 * link, which have taps of their own and used to swallow the press (a `combinedClickable` on the
 * row only sees what its children leave unconsumed). The press is watched in the Initial pass
 * WITHOUT consuming it, so the children's taps and the list's scrolling work as before; moving
 * past touch slop (a scroll, a swipe of the pager), lifting early or a second finger cancels it.
 * Once it fires, the rest of that gesture is consumed so the child does not also see a tap.
 */
fun Modifier.messageLongPress(enabled: Boolean, onLongPress: () -> Unit): Modifier = composed {
    val latest by rememberUpdatedState(onLongPress)
    val haptic = LocalHapticFeedback.current
    if (!enabled) Modifier else Modifier.pointerInput(Unit) {
        awaitEachGesture {
            val down = awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Initial)
            var cancelled = false
            val finished = withTimeoutOrNull(viewConfiguration.longPressTimeoutMillis) {
                while (!cancelled) {
                    val ev = awaitPointerEvent(PointerEventPass.Initial)
                    val c = ev.changes.firstOrNull { it.id == down.id }
                    if (c == null || !c.pressed || ev.changes.size > 1 ||
                        (c.position - down.position).getDistance() > viewConfiguration.touchSlop) cancelled = true
                }
            }
            if (finished != null || cancelled) return@awaitEachGesture
            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
            latest()
            do {
                val ev = awaitPointerEvent(PointerEventPass.Initial)
                ev.changes.forEach { it.consume() }
            } while (ev.changes.any { it.pressed })
        }
    }
}

/** True for a short all-emoji message — rendered oversized (matches iOS isEmojiOnly). */
fun isEmojiOnly(s: String): Boolean {
    val t = s.trim()
    if (t.isEmpty() || t.length > 8) return false
    return t.all { c ->
        val type = Character.getType(c)
        type == Character.SURROGATE.toInt() || type == Character.OTHER_SYMBOL.toInt() ||
            type == Character.NON_SPACING_MARK.toInt() || c == '‍' || c == ' ' ||
            c.code in 0x1F000..0x1FAFF || c.code in 0x2600..0x27BF || c.code in 0xFE00..0xFE0F
    }
}

/**
 * Render text large if it's emoji-only, else with inline markdown (bold/italic/`code`) and links.
 *
 * Links are made honest (see [LinkPolicy]): a label that hides its address gets the real address
 * beside it, only http/https/mailto are links, and a tap shows the full address and asks before
 * anything opens.
 */
@Composable
fun MarkdownOrEmoji(text: String, mentions: List<Mentions.Mention> = emptyList()) {
    if (mentions.isEmpty() && isEmojiOnly(text)) {
        Text(text, fontSize = 40.sp, color = Color.White)
        return
    }
    var pending by remember { mutableStateOf<String?>(null) }
    // A tapped mention: that person's card (the name this device has for them).
    var card by remember { mutableStateOf<Pair<String, String>?>(null) }
    val nameOf = LocalMentionName.current
    val body = remember(text, mentions, nameOf) {
        // Ranges are re-checked against THIS string (in bounds, from '@', sorted, no overlaps).
        val ranges = Mentions.valid(text, mentions)
        if (ranges.isEmpty()) messageText(text) { pending = it }
        else buildAnnotatedString {
            // A mention shows the name THIS device knows for the account (its trust label),
            // never the text the sender typed.
            var at = 0
            for (m in ranges) {
                if (m.start > at) append(messageText(text.substring(at, m.start)) { pending = it })
                val label = nameOf(m.userId, text.substring(m.start + 1, m.start + m.length))
                val style = TextLinkStyles(SpanStyle(color = SkAccent, background = SkAccent.copy(alpha = 0.18f), fontWeight = FontWeight.SemiBold))
                withLink(LinkAnnotation.Clickable("mention:${m.userId}", style) { card = m.userId to label }) { append("@$label") }
                at = m.start + m.length
            }
            if (at < text.length) append(messageText(text.substring(at)) { pending = it })
        }
    }
    Text(body, color = Color.White.copy(alpha = 0.92f))
    pending?.let { url -> ConfirmLinkDialog(url, onClose = { pending = null }) }
    card?.let { (uid, label) -> MentionCard(uid, label, onClose = { card = null }) }
}

/** A mentioned person's card: their avatar, the name this device has for them, and a short id. */
@Composable
fun MentionCard(userId: String, label: String, onClose: () -> Unit) {
    AlertDialog(
        onDismissRequest = onClose,
        title = null,
        text = {
            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                AvatarImage(AvatarStore.userKey(userId), label, size = 64)
                Spacer(Modifier.height(10.dp))
                Text(label, color = Color.White, fontWeight = FontWeight.SemiBold)
                Text("User ${userId.take(8)}…", color = Color.White.copy(alpha = 0.45f), fontFamily = FontFamily.Monospace, fontSize = 12.sp)
            }
        },
        confirmButton = { TextButton(onClick = onClose) { Text("Close") } },
    )
}

/** The message body as text with clickable, honest links. `onLink` gets the address to confirm. */
fun messageText(s: String, onLink: (String) -> Unit): AnnotatedString = buildAnnotatedString {
    val linkStyle = TextLinkStyles(SpanStyle(color = SkAccent, textDecoration = TextDecoration.Underline))
    val targetStyle = TextLinkStyles(SpanStyle(color = Color.White.copy(alpha = 0.55f)))
    for (piece in LinkPolicy.pieces(s)) {
        when (piece) {
            is LinkPolicy.Piece.Text -> append(inlineMarkdown(piece.text))
            is LinkPolicy.Piece.Link -> {
                withLink(LinkAnnotation.Clickable(piece.url, linkStyle) { onLink(piece.url) }) { append(inlineMarkdown(piece.label)) }
                piece.shownTarget?.let { target ->
                    withLink(LinkAnnotation.Clickable(piece.url, targetStyle) { onLink(piece.url) }) { append(" ($target)") }
                }
            }
        }
    }
}

/**
 * How a mention's account is named where messages are shown: (userId, the typed name) → the
 * label. Chat screens provide their trust-labelled lookup; the default is the typed text.
 */
val LocalMentionName = androidx.compose.runtime.staticCompositionLocalOf<(String, String) -> String> { { _, typed -> typed } }

/** Nothing opens on a tap: the full address is shown first and the user decides. */
@Composable
fun ConfirmLinkDialog(url: String, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val clipboard = LocalClipboardManager.current
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("Open this link?") },
        text = {
            Column {
                Text(url, color = Color.White, fontFamily = FontFamily.Monospace, fontSize = 13.sp)
                Spacer(Modifier.height(10.dp))
                Text("This link was sent in a message. Open it only if you recognise the address.",
                    color = Color.White.copy(alpha = 0.7f), fontSize = 13.sp)
            }
        },
        confirmButton = {
            TextButton(onClick = {
                onClose()
                // Re-checked at the last moment: only a web or mail address ever reaches an intent.
                LinkPolicy.openable(url)?.let { ok ->
                    runCatching {
                        ctx.startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(ok))
                            .addCategory(android.content.Intent.CATEGORY_BROWSABLE)
                            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
                    }
                }
            }) { Text("Open") }
        },
        dismissButton = {
            Row {
                TextButton(onClick = { clipboard.setText(AnnotatedString(url)); onClose() }) { Text("Copy address") }
                TextButton(onClick = onClose) { Text("Cancel") }
            }
        },
    )
}

/**
 * Parse inline markdown into an AnnotatedString: **bold**, *italic* / _italic_, `code`. Deliberately
 * small (no block syntax), mirroring iOS's `.inlineOnlyPreservingWhitespace`.
 */
fun inlineMarkdown(s: String): AnnotatedString = buildAnnotatedString {
    var i = 0
    fun emphasisRun(marker: String, style: SpanStyle): Boolean {
        if (!s.startsWith(marker, i)) return false
        val end = s.indexOf(marker, i + marker.length)
        if (end < 0) return false
        withStyle(style) { append(s.substring(i + marker.length, end)) }
        i = end + marker.length
        return true
    }
    while (i < s.length) {
        when {
            emphasisRun("**", SpanStyle(fontWeight = FontWeight.Bold)) -> {}
            emphasisRun("`", SpanStyle(fontFamily = FontFamily.Monospace,
                background = Color.White.copy(alpha = 0.10f))) -> {}
            emphasisRun("*", SpanStyle(fontStyle = FontStyle.Italic)) -> {}
            emphasisRun("_", SpanStyle(fontStyle = FontStyle.Italic)) -> {}
            else -> { append(s[i]); i++ }
        }
    }
}

private fun shortTime(epochMs: Long): String {
    if (epochMs <= 0) return ""
    val d = java.util.Date(epochMs)
    return java.text.SimpleDateFormat("h:mm a", java.util.Locale.getDefault()).format(d)
}

/** Build 49: the mark after a mention chip's plain name (a chip is text: a small "?" for a name
 *  only the server vouches for, the flag's word for a flagged one, nothing for a known name). */
fun chipMark(shown: ContactTrust.Shown): String = when {
    shown.flag != ContactTrust.Flag.NONE -> " (${shown.flag.mark})"
    shown.unverified -> " ?"
    else -> ""
}

/**
 * The mark that goes next to a person's name wherever one is shown: a badge for a contact whose
 * safety number the user verified, a quiet "unverified" for a name that is only the server's
 * word, and a loud warning for a name that reads like someone the user knows but is a different
 * account. A name the user pinned themself (KNOWN) carries no mark.
 */
@Composable
fun NameTrustMark(shown: ContactTrust.Shown) {
    when {
        // Strong flags (impersonation, unusual characters, name doesn't match) in red; "couldn't check" in amber.
        shown.flag != ContactTrust.Flag.NONE -> {
            Spacer(Modifier.width(6.dp))
            Text(shown.flag.mark, color = if (shown.strong) Color(0xFFF87171) else Color(0xFFFFA726), fontSize = 10.sp,
                fontWeight = if (shown.strong) FontWeight.SemiBold else FontWeight.Normal, maxLines = 1)
        }
        shown.verified -> {
            Spacer(Modifier.width(4.dp))
            Icon(Icons.Filled.VerifiedUser, "Verified", tint = Color(0xFF4ADE80), modifier = Modifier.size(13.dp))
        }
        shown.unverified -> {
            Spacer(Modifier.width(6.dp))
            Text("unverified", color = Color.White.copy(alpha = 0.35f), fontSize = 10.sp, maxLines = 1)
        }
    }
}

/**
 * While the composer ends in "@…": the people (user id, how this device shows them, username)
 * whose label or username matches, best first; a tap inserts the USERNAME's token
 * ([Mentions.tokenFor], [Mentions.complete]) and reports the pick.
 */
@Composable
fun MentionSuggestions(draft: String, candidates: List<Triple<String, ContactTrust.Shown, String>>, onPick: (String, String) -> Unit) {
    val q = Mentions.query(draft) ?: return
    val byId = candidates.associateBy { it.first }
    val matches = Mentions.matches(q, candidates.map { Mentions.Candidate(it.first, it.second.label, it.third) })
    if (matches.isEmpty()) return
    Column(Modifier.fillMaxWidth().padding(horizontal = 4.dp)) {
        matches.forEach { c ->
            val uid = c.userId
            val shown = byId[uid]?.second ?: return@forEach
            Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).clickable { onPick(uid, Mentions.tokenFor(c)) }
                .padding(horizontal = 8.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                AvatarImage(AvatarStore.userKey(uid), shown.label, size = 24)
                Spacer(Modifier.width(8.dp))
                Text(shown.label, color = Color.White, fontSize = 14.sp)
                NameTrustMark(shown)
            }
        }
    }
}

/** The red "@ n": unseen mentions of me ([AppModel.mentionCount]); nothing when there are none. */
@Composable
fun MentionBadge(count: Int, modifier: Modifier = Modifier) {
    if (count <= 0) return
    Text("@ ${if (count > 99) "99+" else count}", color = Color.White, fontSize = 10.sp, fontWeight = FontWeight.Bold,
        modifier = modifier.background(Color(0xFFEF4444), RoundedCornerShape(50)).padding(horizontal = 5.dp, vertical = 1.dp)
            .semantics { contentDescription = "$count unseen mention${if (count == 1) "" else "s"}" })
}
