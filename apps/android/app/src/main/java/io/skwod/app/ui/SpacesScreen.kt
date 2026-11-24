package io.skwod.app

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.waitForUpOrCancellation
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.skwod_core.Message

/**
 * A single channel's E2EE conversation — the chat page of the drawer. Header carries a back affordance
 * (swipe-back on the pager also works) and an invite button that opens the secure-join sheet.
 */
@Composable
fun ChannelView(space: RealSpace, onBack: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val me = model.session?.userId ?: return
    val scope = rememberCoroutineScope()
    val messages = remember { mutableStateListOf<Message>() }
    val listState = rememberLazyListState()
    val ctx = LocalContext.current
    var draft by remember { mutableStateOf("") }
    var sending by remember { mutableStateOf(false) }
    var sendError by remember { mutableStateOf<String?>(null) }
    var showInvite by remember { mutableStateOf(false) }
    var uploading by remember { mutableStateOf(false) }
    var gameMenu by remember { mutableStateOf(false) }
    var activeGame by remember { mutableStateOf<String?>(null) }
    var showMembers by remember { mutableStateOf(false) }
    // userId -> real username, so channel rows show names instead of an id prefix (matches iOS).
    val memberNames = remember { mutableStateMapOf<String, String>() }
    // Message actions: reply/edit targets, a forward target, and per-message reactions.
    var replyingTo by remember { mutableStateOf<Message?>(null) }
    var editing by remember { mutableStateOf<Message?>(null) }
    var forwarding by remember { mutableStateOf<Message?>(null) }
    val reactionsByMsg = remember { mutableStateMapOf<String, List<ReactionPill>>() }
    /** Queued sends of this channel, by message id ([Outbox]). */
    val sendStates = remember { mutableStateMapOf<String, SendState>() }
    var blocking by remember { mutableStateOf<SafetyTarget?>(null) }
    var reporting by remember { mutableStateOf<SafetyTarget?>(null) }

    // Pages fetched with "Load older", in front of the live window (`messages`).
    val older = remember(space.channelId) { mutableStateListOf<Message>() }
    var loadingOlder by remember(space.channelId) { mutableStateOf(false) }
    var reachedStart by remember(space.channelId) { mutableStateOf(false) }

    /** Every reaction of the channel in ONE cache read (as of the last sync) — not one request per message. */
    suspend fun refreshReactions() {
        val c = model.client ?: return
        val rows = try { withContext(Dispatchers.IO) { c.channelReactions(space.channelId) } } catch (_: Exception) { return }
        val counts = HashMap<String, LinkedHashMap<String, Pair<Int, Boolean>>>()
        // `emoji` is null when this device could not open the sealed emoji (no space key yet):
        // nothing to show for that row, so it is skipped rather than rendered as a hash.
        for (r in rows) {
            val emoji = r.emoji ?: continue
            val perMessage = counts.getOrPut(r.messageId) { LinkedHashMap() }
            val (n, mineB) = perMessage[emoji] ?: (0 to false)
            perMessage[emoji] = (n + 1) to (mineB || r.userId == me)
        }
        val out = counts.mapValues { (_, v) -> v.map { ReactionPill(it.key, it.value.first, it.value.second) }.sortedBy { it.emoji } }
        reactionsByMsg.clear(); reactionsByMsg.putAll(out)
    }

    /** Which of my messages here are still on their way out, or failed ([Outbox]). */
    suspend fun refreshSendStates() {
        val view = Outbox.states(model, "channel:${space.channelId}")
        sendStates.clear(); sendStates.putAll(view.byMessage)
        view.problem?.let { sendError = it }
    }

    /** Redraw from this device's cache and the outbox — no network (a queued send, a delivery, a block). */
    suspend fun reloadLocal() {
        val c = model.client ?: return
        val rows = withContext(Dispatchers.IO) { c.history("channel:${space.channelId}") }
        messages.clear(); messages.addAll(rows)
        refreshReactions()
        refreshSendStates()
    }

    /** Queue a channel write (shown at once), then let the outbox deliver it. */
    fun queue(failure: String, write: suspend (uniffi.skwod_core.SkwodClient) -> Unit) {
        val c = model.client ?: run { sendError = "Not connected — try again in a moment."; return }
        scope.launch {
            try {
                withContext(Dispatchers.IO) { write(c) }
                reloadLocal()
                Outbox.kick(model)
            } catch (e: Exception) {
                sendError = OutboxPolicy.queueError((e as? uniffi.skwod_core.CoreException.Invalid)?.detail, failure)
            }
        }
    }

    /** Catch up with the server (cheap when nothing changed) and redraw. */
    suspend fun refreshMessages() {
        val asked = model.bound ?: return
        val c = asked.client
        val fresh = withContext(Dispatchers.IO) { c.fetchChannelMessages(space.channelId, me) }
        val authority = model.avatars.authority(space.serverId)
        // Answered for the workspace that was asked: after a switch nothing of it is shown or
        // filed (avatars) in the other one.
        if (model.bound !== asked) return
        // Pick up avatar pointers — each only from whoever may set it (bitmap decode is deferred).
        model.avatars.ingest(fresh, authority)
        if (fresh.isEmpty()) { older.clear(); reachedStart = false }      // the channel was cleared
        messages.clear(); messages.addAll(fresh)
        refreshReactions()
        refreshSendStates()
        model.drainDmEvents()                  // the fetch may have drained the sealed mailbox
    }

    /** "Load older": the next page from the cache, and from the server once the cache runs out. */
    fun loadOlder() {
        if (loadingOlder || reachedStart) return
        val c = model.client ?: return
        loadingOlder = true
        scope.launch {
            try {
                val scopeName = "channel:${space.channelId}"
                var guard = 0
                while (guard++ < 6) {
                    val before = (older.firstOrNull() ?: messages.firstOrNull())?.createdAt ?: break
                    var page = withContext(Dispatchers.IO) { c.historyPage(scopeName, before, HistoryWindow.PAGE.toUInt()) }
                    if (page.isEmpty()) {
                        val fetched = withContext(Dispatchers.IO) { c.loadOlderChannelMessages(space.channelId, me) }
                        if (fetched == 0u) { reachedStart = true; break }
                        page = withContext(Dispatchers.IO) { c.historyPage(scopeName, before, HistoryWindow.PAGE.toUInt()) }
                        if (page.isEmpty()) { reachedStart = true; break }
                    }
                    older.addAll(0, page)
                    // Stop once the page added something the conversation actually shows.
                    val shown = page.count { it.isDeleted || !isFeedHidden(it.content ?: "") }
                    if (shown > 0) { try { listState.scrollToItem(shown) } catch (_: Exception) {}; break }
                }
            } catch (_: Exception) { sendError = "Couldn't load older messages — check your connection." }
            loadingOlder = false
        }
    }

    var attachMenu by remember { mutableStateOf(false) }
    // A picture pasted from the clipboard: previewed (and removable) until Send.
    // It belongs to this channel only ([StagingRule]).
    var pasted by remember(space.channelId) { mutableStateOf<PastedImage?>(null) }
    val onScreen by rememberUpdatedState(space.channelId)
    val clipHasImage = rememberClipboardHasImage()
    // @mentions: who was picked in the composer (user id → the "@name" inserted), the server's
    // pinned owner (whose @everyone counts), and how a mentioned account is named here.
    val mentionPicks = remember { mutableStateListOf<Pair<String, String>>() }
    var pinnedOwner by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(space.serverId) { pinnedOwner = model.pinnedServerOwner(space.serverId); model.refreshEveryoneSenders(space.serverId) }
    // Whose @everyone counts here: the pinned owner and the server's admins ([Mentions.everyoneSenders]).
    val everyoneAllowed = model.everyoneSenders[space.serverId] ?: emptySet()
    // Opening the channel clears its "@ n" (and again whenever a mention lands while it is open).
    LaunchedEffect(space.channelId, model.mentionCount(listOf("channel:${space.channelId}"))) { model.clearMentionBadges("channel:${space.channelId}") }
    val mentionName: (String, String) -> String = { uid, typed ->
        if (uid == model.session?.userId) ContactTrust.SELF_MENTION
        else model.contacts.shown(uid, memberNames[uid] ?: typed).let { s -> s.labelFor(NameSurface.MENTION_CHIP) + chipMark(s) }
    }
    /** The draft as it goes out: the picks still in it ride along, invisibly ([Mentions]). */
    fun withMentions(text: String): String {
        val everyone = Regex("(^|\\s)@everyone(\\b|$)").containsMatchIn(text)
        return Mentions.encode(text, Mentions.locate(text, mentionPicks.toList()), everyone)
    }
    // "I'm typing" at most every few seconds, never for an empty composer ([TypingState]).
    var lastTyping by remember { mutableLongStateOf(0L) }
    fun announceTyping(text: String) {
        val now = System.currentTimeMillis()
        if (TypingState.mayAnnounce(model.settings.typingIndicators, text, lastTyping, now)) {
            lastTyping = now; model.realtime.sendTyping("channel:${space.channelId}")
        }
    }

    var showMusic by remember { mutableStateOf(false) }

    fun sendAttachment(make: suspend () -> Uploads.Prepared) {
        if (model.client == null) { sendError = "Not connected — the file wasn't sent."; return }
        uploading = true; sendError = null
        scope.launch {
            var prepared: Uploads.Prepared? = null
            try {
                // Encrypted file-to-file by the core — nothing is read into memory and nothing
                // is uploaded yet. The message is queued WITH the upload: at the next flush the
                // core uploads it (resuming after a dropped connection or a restart), links the
                // blob to the message — which is what lets everyone else in the channel open it —
                // and sends the message once.
                val up = make()
                prepared = up
                withContext(Dispatchers.IO) { model.client!!.queueChannelMessage(space.channelId, up.body, null, emptyList(), listOf(up.uploadId)) }
                prepared = null
                try { reloadLocal() } catch (_: Exception) {}
                Uploads.watch(model)
                Outbox.kick(model, composed = true)
            } catch (e: AttachmentException) { sendError = e.message
            } catch (e: uniffi.skwod_core.CoreException.Invalid) { sendError = HistoryWindow.sendError(e.detail, "Couldn't send the file.")
            } catch (_: Exception) { sendError = "Couldn't send the file." }
            // Prepared but never queued: drop it again.
            prepared?.let { Uploads.release(model, it.uploadId) }
            uploading = false
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) sendAttachment { Uploads.prepare(ctx, model, uri, forDm = false) }
    }
    val photoPicker = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri != null) sendAttachment { Uploads.prepare(ctx, model, uri, forDm = false) }
    }
    val cameraPicker = rememberLauncherForActivityResult(ActivityResultContracts.TakePicturePreview()) { bmp ->
        if (bmp != null) {
            val out = java.io.ByteArrayOutputStream()
            bmp.compress(android.graphics.Bitmap.CompressFormat.JPEG, 85, out)
            val bytes = out.toByteArray()
            sendAttachment { Uploads.prepareImage(ctx, model, bytes, forDm = false) }
        }
    }

    if (showInvite) {
        SecureJoinScreen(space, onClose = { showInvite = false })
        return
    }
    when (activeGame) {
        "chess" -> {
            Column(Modifier.fillMaxSize()) {
                Row(Modifier.padding(start = 8.dp, top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = { activeGame = null }) { Icon(Icons.Filled.ArrowBack, "Back", tint = Color.White) }
                    Text("Back to #${space.channelName}", color = Color.White.copy(alpha = 0.6f))
                }
                ChessScreen(channelId = space.channelId)
            }
            return
        }
        "whiteboard" -> {
            Column(Modifier.fillMaxSize()) {
                Row(Modifier.padding(start = 8.dp, top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = { activeGame = null }) { Icon(Icons.Filled.ArrowBack, "Back", tint = Color.White) }
                    Text("Back to #${space.channelName}", color = Color.White.copy(alpha = 0.6f))
                }
                WhiteboardScreen(channelId = space.channelId)
            }
            return
        }
    }

    // Make sure every member can read us. One core call does all the key work: it rotates our
    // channel sender key if anyone holding it was kicked/banned/left (or lost a device), then hands
    // the current key — over sealed libsignal sessions — to EVERY device of EVERY member that
    // doesn't hold it yet, including a member's second device and our own other devices.
    LaunchedEffect(space.channelId, space.serverId) {
        val c = model.client ?: return@LaunchedEffect
        var tick = 0
        // When someone joins (`member_joined` on the server topic) and on a slow timer — so a
        // member who joins while the channel is open gets keys and a name without anyone
        // leaving and re-entering it, like the Apple app.
        model.realtime.refreshLoop(30_000, match = { it.topic == "server:${space.serverId}" || it.event == "join_request" }) {
            try { withContext(Dispatchers.IO) { c.syncChannelMembership(space.channelId, space.serverId, me) } } catch (_: Exception) {}
            // Whoever that sync left without keys is waiting for someone to let them in.
            model.waiting.refresh(space.serverId)
            if (tick % 2 == 0 || memberNames.isEmpty()) {
                val members = try { withContext(Dispatchers.IO) { c.listMembers(space.serverId) } } catch (_: Exception) { emptyList() }
                for (m in members) memberNames[m.userId] = m.username
                // Keep the set of names nobody else may wear (accepted members) current.
                model.refreshRoster()
            }
            tick++
        }
    }

    if (showMembers) {
        MembersSheet(space.serverId, space.name, onClose = { showMembers = false })
        return
    }

    LaunchedEffect(space.channelId) {
        val c = model.client ?: return@LaunchedEffect
        messages.clear(); messages.addAll(withContext(Dispatchers.IO) { c.history("channel:${space.channelId}") })
        // Driven by the WebSocket: the channel is re-read when the relay says something happened
        // in it (a message, an edit, a delete, a reaction, a clear), when the socket reconnects,
        // and on a slow safety timer — not every two seconds.
        val topic = "channel:${space.channelId}"
        model.realtime.refreshLoop(45_000, match = { it.topic == topic }) { Outbox.flush(model); refreshMessages() }
    }
    val all = HistoryWindow.merge(older, messages, { it.messageId }, { it.createdAt })
    // Feed posts, stories, comments, and game moves ride this channel but belong to the Feed /
    // game views, not the conversation — hide them here (attachments/music DO show).
    val visible = all.filter { it.isDeleted || !isFeedHidden(it.content ?: "") }
    // Follow the conversation when something NEW arrives at the end (not when older pages load).
    val newestId = visible.lastOrNull()?.messageId
    // Something was queued, delivered or failed — or someone was blocked: redraw from the cache.
    val outboxRevision = Outbox.revision.intValue
    LaunchedEffect(outboxRevision) { if (outboxRevision > 0) try { reloadLocal() } catch (_: Exception) {} }
    // ---- build 49: what is new since this device last read the channel ----
    val readKey = model.current?.id?.let { io.skwod.app.UnreadRule.storageKey(it, space.channelId) }
    var marker by remember(space.channelId) { mutableStateOf<io.skwod.app.ReadMarker?>(null) }
    var markerLoaded by remember(space.channelId) { mutableStateOf(false) }
    // Frozen at open: the divider stays where the new messages began while they are read.
    var unreadAtOpen by remember(space.channelId) { mutableStateOf<Triple<String, Int, Long>?>(null) }
    var positioned by remember(space.channelId) { mutableStateOf(false) }
    var barDismissed by remember(space.channelId) { mutableStateOf(false) }
    var lastSeenId by remember(space.channelId) { mutableStateOf<String?>(null) }
    val atBottom by remember { derivedStateOf { !listState.canScrollForward } }
    val unreadItems = visible.map { io.skwod.app.UnreadItem(it.messageId, it.createdAt, it.authorId == "__me__" || it.authorId == me, it.isSystem) }
    LaunchedEffect(space.channelId, readKey) {
        val c = model.client
        marker = if (c != null && readKey != null) io.skwod.app.ReadMarker.decode(try { withContext(Dispatchers.IO) { c.kvRead(readKey) } } catch (_: Exception) { null }) else null
        markerLoaded = true
    }
    // Opens at the first unread message (the divider a little below the top), else at the newest.
    LaunchedEffect(markerLoaded, newestId != null) {
        if (!markerLoaded || positioned || newestId == null) return@LaunchedEffect
        positioned = true
        val first = io.skwod.app.UnreadRule.firstUnreadIndex(unreadItems, marker)
        unreadAtOpen = first?.let { Triple(unreadItems[it].id, io.skwod.app.UnreadRule.unreadCount(unreadItems, marker), unreadItems[it].createdAt) }
        lastSeenId = newestId
        // +1: the "load older" row is item 0.
        listState.scrollToItem(if (first != null) first + 1 else visible.size)
    }
    // Follow new messages only while at the bottom (or my own); otherwise the pill counts them.
    LaunchedEffect(newestId) {
        if (newestId == null || !positioned) return@LaunchedEffect
        if (atBottom || unreadItems.lastOrNull()?.mine == true) { listState.animateScrollToItem(visible.size); lastSeenId = newestId }
    }
    // At the newest message: read up to it (kept in the encrypted cache, one key per channel).
    LaunchedEffect(atBottom, newestId, positioned) {
        if (!atBottom || !positioned) return@LaunchedEffect
        val last = unreadItems.lastOrNull() ?: return@LaunchedEffect
        lastSeenId = last.id
        val next = io.skwod.app.UnreadRule.advanced(marker, last)
        if (next == marker) return@LaunchedEffect
        marker = next
        val c = model.client ?: return@LaunchedEffect
        if (readKey != null) try { withContext(Dispatchers.IO) { c.kvWrite(readKey, next.encode()) } } catch (_: Exception) {}
    }
    val newBelow = if (atBottom) 0 else io.skwod.app.UnreadRule.newBelow(unreadItems, lastSeenId)
    val barText = unreadAtOpen?.takeIf { !barDismissed && io.skwod.app.UnreadRule.unreadCount(unreadItems, marker) > 0 }?.let {
        io.skwod.app.UnreadRule.barText(it.second, java.text.DateFormat.getTimeInstance(java.text.DateFormat.SHORT).format(java.util.Date(it.third)))
    }


    // imePadding lifts the composer above the on-screen keyboard so the input stays visible.
    Column(Modifier.fillMaxSize().imePadding().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) { Icon(Icons.Filled.ArrowBack, "Back", tint = Color.White) }
            Text("#${space.channelName}", color = Color.White, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.weight(1f))
            // People waiting to be let into this server show as a badge on the members button.
            val waitingCount = model.waiting.count(space.serverId)
            IconButton(onClick = { showMembers = true }) {
                BadgedBox(badge = {
                    if (waitingCount > 0) Badge(containerColor = Color(0xFFFFA726), contentColor = Color.Black) {
                        Text(if (waitingCount > 9) "9+" else "$waitingCount")
                    }
                }) {
                    Icon(Icons.Filled.People, if (waitingCount > 0) "Members, $waitingCount waiting to join" else "Members",
                        tint = Color.White.copy(alpha = 0.8f))
                }
            }
            Box {
                IconButton(onClick = { gameMenu = true }) { Icon(Icons.Filled.SportsEsports, "Games", tint = Color.White.copy(alpha = 0.8f)) }
                DropdownMenu(expanded = gameMenu, onDismissRequest = { gameMenu = false }) {
                    DropdownMenuItem(text = { Text("Play chess") }, onClick = { gameMenu = false; activeGame = "chess" },
                        leadingIcon = { Icon(Icons.Filled.GridOn, null) })
                    DropdownMenuItem(text = { Text("Whiteboard") }, onClick = { gameMenu = false; activeGame = "whiteboard" },
                        leadingIcon = { Icon(Icons.Filled.Brush, null) })
                }
            }
            IconButton(onClick = { showInvite = true }) { Icon(Icons.Filled.PersonAdd, "Invite", tint = SkAccent) }
        }
        Spacer(Modifier.height(8.dp))
        // Index bodies so a reply can show a one-line preview of its parent.
        val bodyById = remember(visible) {
            visible.filter { !it.isDeleted && !it.isSystem && !it.isUndecryptable }.associate { it.messageId to
                ((if (it.authorId == "__me__" || it.authorId == me) "you" else MemberLabel.of(model.contacts.shown(it.authorId, memberNames[it.authorId]), it.authorId)) to ChatTags.parse(it.content ?: "").text) }
        }
        Box(Modifier.weight(1f)) {
        LazyColumn(Modifier.fillMaxSize().dismissKeyboardOnTapOrDrag(listState), state = listState) {
            item {
                Box(Modifier.fillMaxWidth().padding(vertical = 4.dp), contentAlignment = Alignment.Center) {
                    when {
                        loadingOlder -> CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = SkAccent)
                        reachedStart -> Text("This is the beginning of #${space.channelName}", color = Color.White.copy(alpha = 0.4f), fontSize = 12.sp)
                        visible.isNotEmpty() -> TextButton(onClick = { loadOlder() }) { Text("Load older messages", color = SkAccent, fontSize = 13.sp) }
                    }
                }
            }
            itemsIndexed(visible) { i, m ->
                if (m.messageId == unreadAtOpen?.first) NewMessagesDivider()
                // What the row IS comes from the flags the core set when it wrote it — never from
                // the author id or the text, which any member controls. A message whose body
                // merely starts with the system or placeholder tag falls through and is drawn
                // as the ordinary message it is.
                when (RowKind.of(m.isSystem, m.isUndecryptable)) {
                    // A security / membership event the core wrote into this channel
                    // ("X joined (approved by Y)", "X added a device"): not a message from anyone.
                    RowKind.SYSTEM -> {
                        // The member list is the server's word: these names go through the contact book too.
                        val nameOf = { id: String -> if (id == me) "You" else MemberLabel.of(model.contacts.shown(id, memberNames[id]), id) }
                        io.skwod.app.SecurityNotices.systemRow(m.content ?: "", nameOf)
                            ?.let { it.settledIfNotWaiting(model.waiting.waiting(space.serverId).any { w -> w.userId == it.userId }, nameOf) }
                            // "Review" on a held member opens the member list, where "Waiting to join" is.
                            ?.let { row -> SystemRow(row, m.createdAt, onAction = if (row.kind == "member_held" && row.actionLabel != null) ({ showMembers = true }) else null) }
                        return@itemsIndexed
                    }
                    // A message this device could not decrypt: its author's device has been asked
                    // to send it again, and the row is replaced in place when it does.
                    RowKind.UNDECRYPTABLE -> {
                        val info = try { uniffi.skwod_core.undecryptablePlaceholder(m) } catch (_: Exception) { null }
                        val from = info?.fromUserId ?: m.authorId
                        val name = model.contacts.shown(from, memberNames[from] ?: (from ?: "member").take(6)).label
                        UndecryptableRowView(UndecryptableRow.text(info?.isFinal ?: true, name), m.createdAt)
                        return@itemsIndexed
                    }
                    RowKind.MESSAGE -> {}
                }
                val mine = m.authorId == "__me__" || (m.authorId != null && m.authorId == me)
                // The member list is the server's word: the name goes through the contact book.
                val shownAuthor = if (mine) null else model.contacts.shown(m.authorId, memberNames[m.authorId] ?: (m.authorId ?: "member").take(6))
                val author = shownAuthor?.name ?: "you"
                val grouped = i > 0 && visible[i - 1].authorId == m.authorId && !visible[i - 1].isSystem && !visible[i - 1].isUndecryptable
                // My rows carry "__me__"; use my real userId so my avatar renders too.
                val authorId = if (mine) model.session?.userId else m.authorId
                val replyPreview = m.replyToId?.let { bodyById[it] }?.let { "${it.first}: ${it.second.take(60)}" }
                val actions = MessageActions(
                    onReact = { emoji ->
                        val already = reactionsByMsg[m.messageId]?.firstOrNull { it.emoji == emoji }?.mine ?: false
                        // The core seals the emoji under the space key; the server only gets a keyed tag.
                        queue("Couldn't change the reaction — try again.") { c ->
                            c.queueReaction(space.channelId, m.messageId, emoji, already)
                            Outbox.flush(model)
                            try { refreshMessages() } catch (_: Exception) {}
                        }
                    },
                    onReply = { editing = null; replyingTo = m },
                    onEdit = { replyingTo = null; editing = m; draft = ChatTags.parse(m.content ?: "").text },
                    onForward = { forwarding = m },
                    onDelete = {
                        older.removeAll { it.messageId == m.messageId }
                        queue("Couldn't delete that message — try again.") { c -> c.queueChannelDelete(space.channelId, m.messageId) }
                    },
                    // The report also tells the owner WHERE the message is (sealed to them only),
                    // so their inbox can look it up in their own copy of the channel.
                    onReport = m.authorId?.let { id -> { reporting = SafetyTarget(id, author, ChatTags.parse(m.content ?: "").text.ifBlank { null }, space.serverId, space.channelId, m.messageId) } },
                    onBlock = m.authorId?.let { id -> { blocking = SafetyTarget(id, author, serverId = space.serverId) } },
                    onRetry = { Outbox.retry(model, it) },
                    onDiscard = { Outbox.discard(model, it, "channel:${space.channelId}", m.messageId) },
                )
                val myId = model.session?.userId ?: ""
                val replyToMine = m.replyToId?.let { id -> visible.firstOrNull { it.messageId == id }?.authorId }?.let { it == "__me__" || it == myId } == true
                val mentionsMe = !mine && Mentions.mentionsMe(ChatTags.parse(m.content ?: "").mentions, myId, m.authorId,
                    everyoneHonoured = Mentions.everyoneHonoured(m.authorId, everyoneAllowed, pinnedOwner), replyToMine = replyToMine)
                MessageRow(author, m.content ?: "", mine, m.createdAt, grouped, authorId,
                    isEdited = m.isEdited, isDeleted = m.isDeleted, replyPreview = replyPreview,
                    reactions = reactionsByMsg[m.messageId] ?: emptyList(), actions = actions, nameTrust = shownAuthor,
                    sendState = if (mine) sendStates[m.messageId] else null, mentionsMe = mentionsMe, mentionName = mentionName)
            }
        }
        // "N new messages since …" across the top, and "↓ N new" while scrolled up.
        barText?.let { text ->
            NewMessagesBar(text, Modifier.align(Alignment.TopCenter).padding(horizontal = 4.dp, vertical = 6.dp),
                onJump = { unreadAtOpen?.first?.let { id -> scope.launch { listState.animateScrollToItem(visible.indexOfFirst { it.messageId == id }.coerceAtLeast(0) + 1) } } },
                onMarkRead = {
                    barDismissed = true
                    unreadItems.lastOrNull()?.let { last ->
                        val next = io.skwod.app.UnreadRule.advanced(marker, last); marker = next
                        val c = model.client
                        if (c != null && readKey != null) scope.launch { try { withContext(Dispatchers.IO) { c.kvWrite(readKey, next.encode()) } } catch (_: Exception) {} }
                    }
                })
        }
        if (newBelow > 0) JumpToNewPill(newBelow, Modifier.align(Alignment.BottomEnd).padding(10.dp)) {
            scope.launch { listState.animateScrollToItem(visible.size) }
        }
        }
        // Reply / edit banner above the composer, with a cancel.
        (editing?.let { "Editing message" } ?: replyingTo?.let { r -> "Replying to ${if (r.authorId == "__me__" || r.authorId == me) "yourself" else MemberLabel.of(model.contacts.shown(r.authorId, memberNames[r.authorId]), r.authorId)}" })?.let { label ->
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp)) {
                Text(label, color = Color.White.copy(alpha = 0.7f), fontSize = 12.sp, modifier = Modifier.weight(1f))
                IconButton(onClick = { if (editing != null) draft = ""; replyingTo = null; editing = null }) {
                    Icon(Icons.Filled.Close, "Cancel", tint = Color.White.copy(alpha = 0.5f))
                }
            }
        }
        sendError?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(4.dp)) }
        // Typing "@…": the members whose names match, to insert as a mention.
        Mentions.query(draft)?.let { q ->
            // Matched on the shown label or the username; the token is the username's.
            val matches = Mentions.matches(q, memberNames.entries.filter { (uid, _) -> uid != model.session?.userId && !model.isBlockedUser(uid) }
                .map { (uid, name) -> Mentions.Candidate(uid, model.contacts.shown(uid, name).label, name) })
            // @everyone is offered to those whose @everyone counts (the pinned owner and admins).
            val offerEveryone = Mentions.everyoneHonoured(model.session?.userId, everyoneAllowed, pinnedOwner) && "everyone".startsWith(q, ignoreCase = true)
            if (offerEveryone) Row(Modifier.fillMaxWidth().padding(horizontal = 4.dp).clip(RoundedCornerShape(10.dp)).clickable {
                draft = Mentions.complete(draft, "@everyone")
            }.padding(horizontal = 8.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("@everyone", color = SkAccent, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.width(8.dp))
                Text("notify everyone here", color = Color.White.copy(alpha = 0.5f), fontSize = 12.sp)
            }
            if (matches.isNotEmpty()) Column(Modifier.fillMaxWidth().padding(horizontal = 4.dp)) {
                matches.forEach { c ->
                    val uid = c.userId
                    val shown = model.contacts.shown(uid, memberNames[uid])
                    Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).clickable {
                        val label = Mentions.tokenFor(c)
                        draft = Mentions.complete(draft, label); mentionPicks.add(uid to label)
                    }.padding(horizontal = 8.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                        AvatarImage(AvatarStore.userKey(uid), shown.label, size = 24)
                        Spacer(Modifier.width(8.dp))
                        Text(shown.label, color = Color.White, fontSize = 14.sp)
                        NameTrustMark(shown)
                    }
                }
            }
        }
        // Only this server's members (as listed) can show as typing here.
        TypingLine("channel:${space.channelId}", accept = { it.isNotEmpty() && it in memberNames },
            nameOf = { model.contacts.shown(it, memberNames[it] ?: it.take(6)).label })
        pasted?.let { p -> PastedImagePreview(p, onRemove = { pasted = null }) }
            ?: run { if (clipHasImage && !uploading && editing == null) PasteImageChip {
                // Tagged with the channel it started in: a picture read after a switch is dropped.
                val startedFor = space.channelId
                scope.launch {
                    val result = try { Result.success(ComposerPaste.take(ctx, model)) } catch (e: AttachmentException) { Result.failure(e) }
                    if (!StagingRule.belongs(startedFor, onScreen)) return@launch
                    result.onSuccess { pasted = it; sendError = null }.onFailure { sendError = it.message }
                }
            } }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box {
                IconButton(onClick = { attachMenu = true }, enabled = !uploading) {
                    if (uploading) CircularProgressIndicator(Modifier.size(22.dp), color = SkAccent)
                    else Icon(Icons.Filled.AddCircle, "Attach", tint = SkAccent)
                }
                DropdownMenu(expanded = attachMenu, onDismissRequest = { attachMenu = false }) {
                    DropdownMenuItem(text = { Text("Take Photo") }, onClick = { attachMenu = false; cameraPicker.launch(null) },
                        leadingIcon = { Icon(Icons.Filled.PhotoCamera, null) })
                    DropdownMenuItem(text = { Text("Photo Library") }, onClick = {
                        attachMenu = false
                        photoPicker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
                    }, leadingIcon = { Icon(Icons.Filled.Image, null) })
                    DropdownMenuItem(text = { Text("Upload a file") }, onClick = { attachMenu = false; picker.launch("*/*") },
                        leadingIcon = { Icon(Icons.Filled.AttachFile, null) })
                    DropdownMenuItem(text = { Text("Share a song") }, onClick = { attachMenu = false; showMusic = true },
                        leadingIcon = { Icon(Icons.Filled.MusicNote, null) })
                }
            }
            OutlinedTextField(draft, { draft = it; announceTyping(it) }, placeholder = { Text("Message #${space.channelName}…", color = Color.White.copy(alpha = 0.4f)) },
                modifier = Modifier.weight(1f), maxLines = 4,
                textStyle = LocalTextStyle.current.copy(color = Color.White),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = Color.White, unfocusedTextColor = Color.White,
                    cursorColor = SkAccent,
                    focusedBorderColor = Color.White.copy(alpha = 0.3f),
                    unfocusedBorderColor = Color.White.copy(alpha = 0.15f)))
            Spacer(Modifier.width(8.dp))
            FilledIconButton(onClick = {
                // A pasted picture goes exactly like one picked with + (stripped, encrypted, queued).
                pasted?.takeIf { editing == null }?.let { pic ->
                    pasted = null
                    sendAttachment { Uploads.prepareImage(ctx, model, pic.bytes, forDm = false) }
                }
                val text = draft.trim(); if (text.isEmpty()) return@FilledIconButton
                lastTyping = 0L
                val outgoing = withMentions(text); mentionPicks.clear()
                val replyTarget = replyingTo; val editTarget = editing
                sendError = null; draft = ""; replyingTo = null; editing = null
                // Nothing here waits for the network: the message is queued in the core (it is
                // in this device's history at once, marked "Sending…") and delivered when the
                // connection allows — typing while offline loses nothing.
                val c = model.client
                scope.launch {
                    try {
                        if (c == null) throw IllegalStateException()
                        withContext(Dispatchers.IO) {
                            if (editTarget != null) c.queueChannelEdit(space.channelId, editTarget.messageId, outgoing)
                            else c.queueChannelMessage(space.channelId, outgoing, replyTarget?.messageId, emptyList(), emptyList())
                        }
                        reloadLocal()
                        Outbox.kick(model, composed = true)
                    } catch (e: Exception) {
                        // Could not even be queued (too long, or the outbox is full): give the text back.
                        draft = text; replyingTo = replyTarget; editing = editTarget
                        sendError = OutboxPolicy.queueError((e as? uniffi.skwod_core.CoreException.Invalid)?.detail)
                    }
                }
            }, enabled = !sending && (draft.isNotBlank() || (pasted != null && editing == null && !uploading)), shape = RoundedCornerShape(50)) {
                Icon(Icons.Filled.ArrowUpward, "Send", tint = Color.Black)
            }
        }
    }

    blocking?.let { BlockDialog(model, it) { blocking = null } }
    reporting?.let { ReportDialog(model, it) { reporting = null } }
    if (showMusic) MusicSearchDialog(
        onPick = { track ->
            showMusic = false
            // The same music card the feed posts and the Apple app sends (`skwod/music|` + the track).
            queue("Couldn't share that song — try again.") { c -> c.queueChannelMessage(space.channelId, ChatTags.MUSIC + track.toJson(), null, emptyList(), emptyList()) }
        },
        onClose = { showMusic = false })
    if (forwarding != null) {
        val target = forwarding!!
        AlertDialog(
            onDismissRequest = { forwarding = null },
            title = { Text("Forward to…") },
            text = {
                LazyColumn {
                    items(model.chat.spaces) { sp ->
                        Row(Modifier.fillMaxWidth().clickable {
                            val body = ChatTags.parse(target.content ?: "").text.ifBlank { "(forwarded message)" }
                            queue("Couldn't forward that message — try again.") { c -> c.queueChannelMessage(sp.channelId, body, null, emptyList(), emptyList()) }
                            forwarding = null
                        }.padding(vertical = 10.dp)) {
                            Text("#${sp.channelName}", color = Color.White)
                            Spacer(Modifier.width(8.dp))
                            Text(sp.name, color = Color.White.copy(alpha = 0.5f), fontSize = 12.sp)
                        }
                    }
                }
            },
            confirmButton = {}, dismissButton = { TextButton(onClick = { forwarding = null }) { Text("Cancel") } }
        )
    }
}

/**
 * Create a server inside the active skwod (owner/host action). Returns a RealSpace for its first
 * channel, which the caller adds to the sidebar.
 */
@Composable
fun CreateServerDialog(onCancel: () -> Unit, onCreate: (RealSpace) -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf("") }
    var channel by remember { mutableStateOf("general") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = { if (!busy) onCancel() },
        confirmButton = {
            TextButton(onClick = {
                if (busy) return@TextButton
                busy = true; error = null
                scope.launch {
                    try {
                        val s = withContext(Dispatchers.IO) { model.client!!.createSpace(name.trim(), channel.trim()) }
                        onCreate(RealSpace(name.trim(), channel.trim(), s.serverId, s.channelId, s.inviteCode, s.spaceKeyHex))
                    } catch (e: Exception) { error = "Couldn't create the server." }
                    busy = false
                }
            }, enabled = !busy && name.isNotBlank()) { Text(if (busy) "…" else "Create") }
        },
        dismissButton = { TextButton(onClick = onCancel, enabled = !busy) { Text("Cancel") } },
        title = { Text("Create a server") },
        text = {
            Column {
                Text("A server lives in your Skwod and holds its own channels and members.",
                    color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(name, { name = it }, label = { Text("Server name") }, singleLine = true)
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(channel, { channel = it }, label = { Text("First channel") }, singleLine = true)
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        }
    )
}

/** The line above the first message that was new when the channel opened (build 49). */
@Composable
private fun NewMessagesDivider() {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.weight(1f).height(1.dp).background(Color(0xFFE5484D)))
        Spacer(Modifier.width(6.dp))
        Text("NEW", color = Color.White, fontSize = 10.sp, fontWeight = FontWeight.Black,
            modifier = Modifier.clip(RoundedCornerShape(4.dp)).background(Color(0xFFE5484D)).padding(horizontal = 6.dp, vertical = 2.dp))
    }
}

/** "3 new messages since 4:12 PM" — tap to jump to the first of them, or mark them read. */
@Composable
private fun NewMessagesBar(text: String, modifier: Modifier, onJump: () -> Unit, onMarkRead: () -> Unit) {
    Row(modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(SkAccent).padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Text("↑ $text", color = Color.Black, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, maxLines = 1,
            modifier = Modifier.weight(1f).clickable(onClick = onJump))
        Text("Mark as read", color = Color.Black, fontSize = 13.sp, fontWeight = FontWeight.Bold, modifier = Modifier.clickable(onClick = onMarkRead))
    }
}

/** "↓ 2 new" while scrolled up and messages arrive below. */
@Composable
private fun JumpToNewPill(count: Int, modifier: Modifier, onTap: () -> Unit) {
    Text("↓ $count new", color = Color.Black, fontSize = 13.sp, fontWeight = FontWeight.SemiBold,
        modifier = modifier.clip(RoundedCornerShape(50)).background(SkAccent).clickable(onClick = onTap).padding(horizontal = 12.dp, vertical = 8.dp))
}

/**
 * Build 49: the keyboard goes away the usual ways — a tap on the conversation, or dragging it.
 * The tap is watched on the Initial pass and never consumed, so links, pictures, reactions and
 * the long press still get theirs.
 */
@Composable
internal fun Modifier.dismissKeyboardOnTapOrDrag(listState: androidx.compose.foundation.lazy.LazyListState): Modifier {
    val focus = androidx.compose.ui.platform.LocalFocusManager.current
    val keyboard = androidx.compose.ui.platform.LocalSoftwareKeyboardController.current
    LaunchedEffect(listState) {
        androidx.compose.runtime.snapshotFlow { listState.isScrollInProgress }.collect { scrolling ->
            if (scrolling) { keyboard?.hide(); focus.clearFocus() }
        }
    }
    return this.pointerInput(Unit) {
        awaitEachGesture {
            val down = awaitFirstDown(requireUnconsumed = false, pass = androidx.compose.ui.input.pointer.PointerEventPass.Initial)
            val up = waitForUpOrCancellation(pass = androidx.compose.ui.input.pointer.PointerEventPass.Initial)
            if (up != null && (up.position - down.position).getDistance() < viewConfiguration.touchSlop) {
                keyboard?.hide(); focus.clearFocus()
            }
        }
    }
}
