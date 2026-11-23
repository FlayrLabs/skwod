package io.skwod.app

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.skwod_core.Message

/**
 * The home surface behind the skwod rail icon: your Direct Message conversations.
 * New chats are started by username; opening one drives the sidebar selection so the pager slides
 * to the chat page.
 */
@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
fun DmHomeView(chat: AppChat) {
    val model = AppModel.get(LocalContext.current)
    var showNew by remember { mutableStateOf(false) }
    var showNewGroup by remember { mutableStateOf(false) }
    // Groups come from the core's own list (never from the 1:1 list). Read on open; the app
    // keeps it current as messages arrive.
    val groupsRevision = model.groups.revision.intValue
    LaunchedEffect(model.current?.id) { model.groups.refresh() }
    // Someone blocked leaves the list at once (the core stops listing them; this is the same
    // rule applied to what is already on screen).
    val blocked = BlockList.ids
    val dms = chat.dms.filter { it.peerUserId !in blocked }
    // Long-press on a conversation: mute it (for a while, or until unmuted).
    var muteFor by remember { mutableStateOf<String?>(null) }
    muteFor?.let { key -> MuteDialog(model, key) { muteFor = null } }
    val groups = remember(groupsRevision, blocked) { model.groups.list.filter { g -> g.others.none { it in blocked } } }
    // Conversations the server lists that this device has not accepted: shown as invitations,
    // never as groups, and never with anything that was written in them.
    val invitations = remember(groupsRevision, blocked) { model.groups.invitations.filter { g -> g.others.none { it in blocked } } }
    var inviteFor by remember { mutableStateOf<GroupConversation?>(null) }

    Column(Modifier.fillMaxSize().padding(20.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            ScreenTitle("Messages", subtitle = "end-to-end encrypted")
            Spacer(Modifier.weight(1f))
            IconButton(onClick = { showNewGroup = true }) { Icon(Icons.Filled.GroupAdd, "New group", tint = SkAccent) }
            IconButton(onClick = { showNew = true }) { Icon(Icons.Filled.Edit, "New", tint = SkAccent) }
        }
        Spacer(Modifier.height(12.dp))
        ConversationNotices()
        if (dms.isEmpty() && groups.isEmpty() && invitations.isEmpty()) {
            Text("No conversations yet — start an encrypted chat.", color = Color.White.copy(alpha = 0.5f))
        } else {
            LazyColumn {
                items(invitations, key = { "invite|" + it.conversationId }) { g ->
                    ListItem(
                        headlineContent = { Text(GroupRules.INVITATION_TITLE, color = Color.White, maxLines = 1) },
                        supportingContent = { Text(GroupRules.invitationLine(g.others.size), color = Color.White.copy(alpha = 0.55f)) },
                        leadingContent = {
                            Box(Modifier.size(46.dp).clip(RoundedCornerShape(50)).background(SkAccent), contentAlignment = Alignment.Center) {
                                Icon(Icons.Filled.Groups, null, tint = Color.Black)
                            }
                        },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                        modifier = Modifier.clickable { inviteFor = g }
                    )
                    HorizontalDivider(color = Color.White.copy(alpha = 0.06f))
                }
                items(groups, key = { "group|" + it.conversationId }) { g ->
                    ListItem(
                        headlineContent = { Text(model.groups.title(g), color = Color.White, maxLines = 1, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis) },
                        supportingContent = { Text("${g.others.size + 1} people · encrypted", color = SkAccentWash) },
                        leadingContent = {
                            Box(Modifier.size(46.dp).clip(RoundedCornerShape(50)).background(Color.White.copy(alpha = 0.08f)), contentAlignment = Alignment.Center) {
                                Icon(Icons.Filled.Groups, "Group", tint = Color.White.copy(alpha = 0.8f))
                            }
                        },
                        trailingContent = { Row(verticalAlignment = Alignment.CenterVertically) { MentionBadge(model.mentionCount(listOf("dm:${g.conversationId}"))); MutedMark(model, "dm:${g.conversationId}") } },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                        modifier = Modifier.combinedClickable(onClick = { chat.selection = SidebarItem.Group(g) },
                            onLongClick = { muteFor = "dm:${g.conversationId}" })
                    )
                    HorizontalDivider(color = Color.White.copy(alpha = 0.06f))
                }
                items(dms, key = { it.key }) { d ->
                    // Live presence dot + label (reads realtime.presence state → auto-recomposes).
                    val status = model.realtime.status(d.peerUserId)
                    // The name comes from the contact book, never straight from the server's list.
                    val shown = model.contacts.shown(d.peerUserId, d.name)
                    ListItem(
                        headlineContent = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(shown.name, color = if (shown.strong) Color(0xFFF87171) else Color.White, maxLines = 1)
                                NameTrustMark(shown)
                            }
                        },
                        supportingContent = {
                            when {
                                shown.impersonation -> Text("Looks like someone you know, but is a different account", color = Color(0xFFF87171))
                                shown.strong -> Text("Don't rely on this name", color = Color(0xFFF87171))
                                d.isSplit -> Text("Arrived inside someone else's conversation", color = Color(0xFFFFA726))
                                else -> Text(if (status == "offline") "encrypted" else presenceLabel(status),
                                    color = if (status == "offline") SkAccentWash else presenceColor(status))
                            }
                        },
                        leadingContent = {
                            Box {
                                AvatarImage(AvatarStore.userKey(d.peerUserId), shown.name, size = 46)
                                Box(Modifier.align(Alignment.BottomEnd).size(13.dp)
                                    .clip(RoundedCornerShape(50)).background(presenceColor(status)))
                            }
                        },
                        trailingContent = { Row(verticalAlignment = Alignment.CenterVertically) { MentionBadge(model.mentionCount(listOf("dm:${d.conversationId}"))); MutedMark(model, "dm:${d.conversationId}") } },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                        modifier = Modifier.combinedClickable(onClick = { chat.selection = SidebarItem.Dm(d) },
                            onLongClick = { muteFor = "dm:${d.conversationId}" })
                    )
                    HorizontalDivider(color = Color.White.copy(alpha = 0.06f))
                }
            }
        }
    }

    if (showNew) {
        NewDmDialog(onCancel = { showNew = false }, onDone = { showNew = false })
    }
    inviteFor?.let { invitation ->
        GroupInviteDialog(invitation, onClose = { inviteFor = null },
            onJoined = { g -> inviteFor = null; chat.homeMode = false; chat.selection = SidebarItem.Group(g) })
    }
    if (showNewGroup) {
        GroupPickerDialog(title = "New group", confirm = "Start group", fixed = emptyList(),
            onCancel = { showNewGroup = false },
            onPicked = { g -> showNewGroup = false; chat.homeMode = false; chat.selection = SidebarItem.Group(g) })
    }
}

@Composable
private fun NewDmDialog(onCancel: () -> Unit, onDone: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var username by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = { if (!busy) onCancel() },
        confirmButton = {
            TextButton(onClick = {
                if (busy) return@TextButton
                busy = true; error = null
                scope.launch {
                    // Asked, and stored, in the workspace that is current NOW ([AppChat.openDm]). A
                    // refusal is said here — the dialog stays up — instead of closing as if it
                    // had worked.
                    val outcome = model.chat.openDm(username.trim().lowercase())
                    busy = false
                    if (outcome.problem != null) error = outcome.problem else onDone()
                }
            }, enabled = !busy && username.isNotBlank()) { Text(if (busy) "…" else "Start") }
        },
        dismissButton = { TextButton(onClick = onCancel, enabled = !busy) { Text("Cancel") } },
        title = { Text("New encrypted chat") },
        text = {
            Column {
                OutlinedTextField(username, { username = it }, label = { Text("username") }, singleLine = true,
                    leadingIcon = { Icon(Icons.Filled.AlternateEmail, null) })
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        }
    )
}

/** A group conversation: the DM screen, sealed to the group's members as the user sees them. */
@Composable
fun GroupChatView(group: GroupConversation, onBack: () -> Unit) {
    // The 1:1 fields are unused for a group; the entry only carries the conversation id.
    DmChatView(DMConversation("", "", "", group.conversationId), onBack, group)
}

@Composable
fun DmChatView(dm: DMConversation, onBack: () -> Unit, group: GroupConversation? = null) {
    val model = AppModel.get(LocalContext.current)
    val me = model.session?.userId ?: return
    val scope = rememberCoroutineScope()
    val messages = remember { mutableStateListOf<Message>() }
    val listState = rememberLazyListState()
    val ctx = LocalContext.current
    var draft by remember { mutableStateOf("") }
    var sending by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var showVerify by remember { mutableStateOf(false) }
    var uploading by remember { mutableStateOf(false) }
    var showMusic by remember { mutableStateOf(false) }
    var showPeople by remember { mutableStateOf(false) }
    // Where this contact's keys stand (contactStatus), and whether a send of this conversation
    // just failed because it reached nobody (CoreException.IdentityChanged). The banner is
    // decided from these — never from a notice alone ([IdentityHold]).
    var status by remember { mutableStateOf<uniffi.skwod_core.ContactStatus?>(null) }
    var failedHeld by remember { mutableStateOf(false) }
    /** Held failures (outbox ids) already retried once after the contact's status came back clean. */
    val retriedOnce = remember(dm.conversationId) { HashSet<String>() }
    var heldIds by remember(dm.conversationId) { mutableStateOf(emptyList<String>()) }
    val hold = if (group != null) IdentityHold.Banner.NONE else IdentityHold.banner(status?.sendsHeld ?: false,
        (status?.devices ?: 1u).toInt(), (status?.unvouchedDevices ?: 0u).toInt(), failedHeld)
    val sendsHeld = hold == IdentityHold.Banner.HELD
    var verified by remember { mutableStateOf(false) }
    var accepting by remember { mutableStateOf(false) }

    // What this person is called, and how far that is trusted, comes from the contact book.
    val shown = model.contacts.shown(dm.peerUserId, dm.name)
    val peerName = if (group != null) model.groups.title(group) else shown.name
    /** Who wrote a row, as this device names them: the one peer, or a member of the group. */
    fun shownAuthor(authorId: String?): ContactTrust.Shown = if (group != null && authorId != null) model.groups.shown(authorId, group) else shown
    // Pages read with "Load older" (from this device's cache), in front of the live window.
    val older = remember(dm.conversationId) { mutableStateListOf<Message>() }
    var reachedStart by remember(dm.conversationId) { mutableStateOf(false) }
    val scopeName = "dm:${dm.conversationId}"

    /** Queued sends of this conversation, by message id ([Outbox]); reactions per message. */
    val sendStates = remember(dm.conversationId) { mutableStateMapOf<String, SendState>() }
    val reactionsByMsg = remember(dm.conversationId) { mutableStateMapOf<String, List<ReactionPill>>() }
    var replyingTo by remember(dm.conversationId) { mutableStateOf<Message?>(null) }
    var editing by remember(dm.conversationId) { mutableStateOf<Message?>(null) }
    // @mentions (build 46): who was picked in the composer (user id → the "@name" inserted); they
    // ride inside the encrypted text ([Mentions]). No @everyone in a direct or group conversation.
    val mentionPicks = remember(dm.conversationId) { mutableStateListOf<Pair<String, String>>() }
    val mentionName: (String, String) -> String = { uid, _ ->
        if (uid == me) (model.current?.username ?: "you") else shownAuthor(uid).label
    }
    // Opening the conversation clears its "@ n" (and again whenever a mention lands while it is open).
    LaunchedEffect(scopeName, model.mentionCount(listOf(scopeName))) { model.clearMentionBadges(scopeName) }
    var blocking by remember { mutableStateOf<SafetyTarget?>(null) }
    var reporting by remember { mutableStateOf<SafetyTarget?>(null) }
    /**
     * Who a message of this conversation is sealed to — and every edit, delete, reaction and
     * attachment with it: the one other person, or the group's STORED member set (the people
     * the user picked, or saw when joining). Never a list taken from the server.
     */
    val peers = group?.others ?: listOf(dm.peerUserId)

    /**
     * Held failures while the contact's status is CLEAN (accepted elsewhere — the notice's
     * Accept, another screen): retried once each, and the banner shows only if a retry fails
     * again. While the status itself holds, they keep the banner up.
     */
    fun settleHeld() {
        val st = status
        val clean = st != null && IdentityHold.banner(st.sendsHeld, st.devices.toInt(), st.unvouchedDevices.toInt(), false) == IdentityHold.Banner.NONE
        if (!clean) { failedHeld = heldIds.isNotEmpty(); return }
        val fresh = heldIds.filter { it !in retriedOnce }
        failedHeld = heldIds.any { it in retriedOnce }
        if (fresh.isNotEmpty()) { retriedOnce += fresh; scope.launch { Outbox.retryAll(model, fresh) } }
    }

    /** Reactions and send states (both local). */
    suspend fun loadOverlays() {
        val c = model.client ?: return
        val rows = try { withContext(Dispatchers.IO) { c.dmReactions(dm.conversationId) } } catch (_: Exception) { emptyList() }
        // A reaction counts only if I made it or someone this conversation is WITH did: the one
        // peer, or a member of the group's stored set — never any account that knows a message id.
        val grouped = rows.filter { ReactionRules.counts(it.userId, me, peers) }.groupBy { it.messageId }.mapValues { (_, list) ->
            list.filter { it.emoji != null }.groupBy { it.emoji!! }.map { (emoji, who) -> ReactionPill(emoji, who.size, who.any { it.userId == me }) }.sortedBy { it.emoji }
        }
        reactionsByMsg.clear(); reactionsByMsg.putAll(grouped)
        val view = Outbox.states(model, scopeName)
        sendStates.clear(); sendStates.putAll(view.byMessage)
        view.problem?.let { error = it }
        // A send that reached nobody because this contact's keys changed: it stays "not delivered".
        heldIds = view.byMessage.values.filterIsInstance<SendState.Failed>().filter { IdentityHold.isHeldFailure(it.reason) }.map { it.localId }
        settleHeld()
    }

    /** Re-read the conversation from the cache (no network). */
    suspend fun reload() {
        val c = model.client ?: return
        val rows = try { withContext(Dispatchers.IO) { c.history(scopeName) } } catch (_: Exception) { return }
        messages.clear(); messages.addAll(rows)
        loadOverlays()
    }

    /** Queue a DM write (shown at once), then let the outbox deliver it to every device of both people. */
    fun queue(failure: String, write: suspend (uniffi.skwod_core.SkwodClient) -> Unit) {
        val c = model.client ?: run { error = "Not connected — try again in a moment."; return }
        scope.launch {
            try {
                withContext(Dispatchers.IO) { write(c) }
                reload()
                Outbox.kick(model)
            } catch (e: Exception) {
                error = OutboxPolicy.queueError((e as? uniffi.skwod_core.CoreException.Invalid)?.detail, failure)
            }
        }
    }

    fun loadOlder() {
        val c = model.client ?: return
        val before = (older.firstOrNull() ?: messages.firstOrNull())?.createdAt ?: return
        scope.launch {
            val page = try { withContext(Dispatchers.IO) { c.historyPage(scopeName, before, HistoryWindow.PAGE.toUInt()) } } catch (_: Exception) { emptyList() }
            if (page.isEmpty()) reachedStart = true
            else { older.addAll(0, page); try { listState.scrollToItem(page.size) } catch (_: Exception) {} }
        }
    }

    suspend fun refreshStatus() {
        if (group != null) return       // trust is per person: "People" shows each member's
        val asked = model.client ?: return
        val st = try { withContext(Dispatchers.IO) { asked.contactStatus(dm.peerUserId) } } catch (_: Exception) { null } ?: return
        // This workspace's answer is only for this workspace's contact book.
        if (model.client !== asked) return
        fun statusHolds(s: uniffi.skwod_core.ContactStatus?) = s != null &&
            IdentityHold.banner(s.sendsHeld, s.devices.toInt(), s.unvouchedDevices.toInt(), false) == IdentityHold.Banner.HELD
        val wasHeld = statusHolds(status)
        status = st; verified = st.verified
        // The hold was lifted (accepted, or verified again on the safety-number screen): what
        // failed while it held goes out now.
        if (wasHeld && !statusHolds(st)) { failedHeld = false; Outbox.retryAll(model, IdentityHold.toRetry(sendStates)) }
        else settleHeld()
        // The contact book follows the safety-number state: verifying promotes to VERIFIED,
        // losing it falls back to KNOWN.
        model.contacts.setVerified(dm.peerUserId, st.verified, dm.name)
    }

    // "I'm typing" at most every few seconds, never for an empty composer ([TypingState]).
    var lastTyping by remember { mutableLongStateOf(0L) }
    fun announceTyping(text: String) {
        val now = System.currentTimeMillis()
        if (TypingState.mayAnnounce(model.settings.typingIndicators, text, lastTyping, now)) {
            lastTyping = now; model.realtime.sendTyping(scopeName)
        }
    }

    /** Send, reply or edit — queued in the core (shown at once as "Sending…"). */
    fun sendDraft() {
        val typed = draft.trim(); if (typed.isEmpty()) return
        val text = Mentions.encode(typed, Mentions.locate(typed, mentionPicks.toList()))
        mentionPicks.clear()
        lastTyping = 0L
        val replyTarget = replyingTo; val editTarget = editing
        error = null; draft = ""; replyingTo = null; editing = null
        val c = model.client
        scope.launch {
            try {
                if (c == null) throw IllegalStateException()
                withContext(Dispatchers.IO) {
                    if (editTarget != null) c.queueDmEdit(dm.conversationId, peers, editTarget.messageId, text)
                    else c.queueDm(dm.conversationId, peers, text, replyTarget?.messageId, emptyList())
                }
                // Writing in a conversation is the user taking it: it now claims its id.
                model.chat.claimDM(dm)
                reload()
                Outbox.kick(model, composed = true)
            } catch (e: Exception) {
                // Could not even be queued: give the text back without clobbering anything typed meanwhile.
                draft = if (draft.isEmpty()) text else "$text\n$draft"
                replyingTo = replyTarget; editing = editTarget
                error = OutboxPolicy.queueError((e as? uniffi.skwod_core.CoreException.Invalid)?.detail)
            }
        }
    }

    // A picture pasted from the clipboard: previewed (and removable) until Send.
    // It belongs to this conversation only ([StagingRule]).
    var pasted by remember(dm.conversationId) { mutableStateOf<PastedImage?>(null) }
    val onScreen by rememberUpdatedState(dm.conversationId)
    val clipHasImage = rememberClipboardHasImage()

    /** Prepare a file (picked, or a pasted picture) and queue it in this conversation. */
    fun sendFile(make: suspend () -> Uploads.Prepared) {
        uploading = true; error = null
        scope.launch {
            var prepared: Uploads.Prepared? = null
            try {
                // Encrypted file-to-file by the core (nothing is uploaded yet), then queued WITH
                // the upload: it goes out — and resumes — whenever the connection allows. A DM
                // leaves nothing on the server that access to the blob could hang on, so the
                // descriptor carries a download token: whoever can read the message can fetch the file.
                val up = make()
                prepared = up
                withContext(Dispatchers.IO) { model.client!!.queueDm(dm.conversationId, peers, up.body, null, listOf(up.uploadId)) }
                model.chat.claimDM(dm)
                prepared = null
                reload()
                Uploads.watch(model)
                Outbox.kick(model, composed = true)
            } catch (_: uniffi.skwod_core.CoreException.IdentityChanged) {
                failedHeld = true; error = "Not delivered — ${peerName}'s security key changed. Accept or verify it, then attach the file again."
            } catch (e: AttachmentException) { error = e.message
            } catch (e: uniffi.skwod_core.CoreException.Invalid) { error = HistoryWindow.sendError(e.detail, "Couldn't send the file.")
            } catch (_: Exception) { error = "Couldn't send the file." }
            // Prepared but never queued: nobody holds its key, so drop it (and what reached the host).
            prepared?.let { Uploads.release(model, it.uploadId) }
            uploading = false
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) sendFile { Uploads.prepare(ctx, model, uri, forDm = true) }
    }

    LaunchedEffect(dm.conversationId) {
        val c = model.client ?: return@LaunchedEffect
        reload()
        // The relay's `sealed` event (something is in our mailbox) drives this, plus a slow
        // safety timer and a pass on reconnect — the mailbox is no longer polled every 2 s.
        model.realtime.refreshLoop(45_000, match = { it.event == "sealed" || it.topic == scopeName }) {
            Outbox.flush(model)
            try {
                if (group != null) {
                    // A group has no single peer device to fetch from: sync the mailbox, re-read.
                    model.syncDmsNow()
                    reload()
                } else {
                    val fresh = withContext(Dispatchers.IO) { c.fetchDm(dm.conversationId, dm.peerUserId, dm.peerDeviceId, me) }
                    messages.clear(); messages.addAll(fresh)
                    loadOverlays()
                }
            } catch (e: Exception) { model.routeIfDeviceError(e) }
            // That sync may have brought DMs of OTHER conversations: list and announce them.
            model.drainDmEvents()
            refreshStatus()
        }
    }
    // A DM filed by any other sync (the app-level one, a channel fetch): re-read the cache.
    val dmRevision = model.dmRevision.intValue
    LaunchedEffect(dmRevision) { if (dmRevision > 0) reload() }
    // Queued / delivered / failed, or a block: redraw from the cache.
    val outboxRevision = Outbox.revision.intValue
    LaunchedEffect(outboxRevision) { if (outboxRevision > 0) reload() }
    blocking?.let { BlockDialog(model, it) { blocking = null } }
    reporting?.let { ReportDialog(model, it) { reporting = null } }
    // An entry shows its own peer's messages only. The same server conversation id can carry a
    // sender who is NOT this entry's peer: those are in that sender's own entry, never here.
    // A split-off entry shows only what that sender wrote (our messages went to the bound peer).
    // (What a row IS — a notice the core wrote, a placeholder — comes from its flags, never from
    // its author id or text.) A group shows what its members, as this device lists them, wrote.
    val all = HistoryWindow.merge(older, messages, { it.messageId }, { it.createdAt }).filter { m ->
        val a = m.authorId
        val own = a == null || a == "__me__" || a == me
        // …of the STORED set: a row by anyone else filed under this conversation is not shown.
        if (group != null) m.isSystem || GroupRules.rowShown(a, me, group.others)
        else (!m.isSystem && a == dm.peerUserId) || (!dm.isSplit && (own || m.isSystem))
    }
    val newestId = all.lastOrNull()?.messageId
    LaunchedEffect(newestId) {
        if (newestId != null) listState.animateScrollToItem(all.size)
    }

    if (showMusic) MusicSearchDialog(
        onPick = { track ->
            showMusic = false
            // The same music card the feed and the Apple app send.
            queue("Couldn't share that song — try again.") { c -> c.queueDm(dm.conversationId, peers, ChatTags.MUSIC + track.toJson(), null, emptyList()); model.chat.claimDM(dm) }
        },
        onClose = { showMusic = false })
    if (showPeople && group != null) GroupPeopleDialog(group, onClose = { showPeople = false })
    if (showVerify && group == null) {
        SafetyNumberDialog(peerName, dm.peerUserId,
            onChanged = { scope.launch { refreshStatus() } },
            onClose = { showVerify = false; scope.launch { refreshStatus() } })
    }

    Column(Modifier.fillMaxSize().imePadding().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) { Icon(Icons.Filled.ArrowBack, "Back", tint = Color.White) }
            if (group != null) {
                Icon(Icons.Filled.Groups, null, tint = Color.White.copy(alpha = 0.8f), modifier = Modifier.size(28.dp)); Spacer(Modifier.width(8.dp))
                Text(peerName, color = Color.White, style = MaterialTheme.typography.titleMedium, maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                TextButton(onClick = { showPeople = true }) { Text("People", color = SkAccent) }
            } else {
                AvatarImage(AvatarStore.userKey(dm.peerUserId), peerName, size = 32); Spacer(Modifier.width(8.dp))
                Text(peerName, color = if (shown.strong) Color(0xFFF87171) else Color.White, style = MaterialTheme.typography.titleMedium, maxLines = 1)
                NameTrustMark(shown)
                Spacer(Modifier.weight(1f))
                IconButton(onClick = { showVerify = true }) {
                    when {
                        sendsHeld -> Icon(Icons.Filled.GppMaybe, "Security key changed — messages on hold", tint = Color(0xFFFFA726))
                        verified -> Icon(Icons.Filled.VerifiedUser, "Verified — view safety number", tint = Color(0xFF4ADE80))
                        else -> Icon(Icons.Filled.Shield, "View safety number", tint = SkAccent)
                    }
                }
            }
        }
        Spacer(Modifier.height(8.dp))
        // An unverified name, or one that imitates someone the user knows: say so, and offer
        // the two ways to settle it (compare safety numbers; or vouch for the contact).
        (if (group == null) shown.warning else null)?.let { (text, strong) ->
            val tone = if (strong) Color(0xFFF87171) else Color(0xFFFFA726)
            Column(Modifier.fillMaxWidth().padding(bottom = 6.dp)
                .background(tone.copy(alpha = 0.10f), RoundedCornerShape(12.dp))
                .border(1.dp, tone.copy(alpha = 0.35f), RoundedCornerShape(12.dp)).padding(12.dp)) {
                Text(text, color = Color.White.copy(alpha = 0.85f), style = MaterialTheme.typography.bodySmall)
                Text("Account ${dm.peerUserId.take(8)}" + if (dm.bound) "" else " · listed by the server, no message from them on this device yet",
                    color = Color.White.copy(alpha = 0.5f), style = MaterialTheme.typography.labelSmall)
                Row {
                    TextButton(onClick = { showVerify = true }) { Text("View safety number", color = tone) }
                    // Vouching is the user's own act — and is refused for a name that imitates a known contact.
                    if (shown.flag == ContactTrust.Flag.NONE && shown.name != ContactTrust.UNKNOWN) {
                        TextButton(onClick = { model.contacts.markKnown(dm.peerUserId, shown.name) }) { Text("I know them — accept") }
                    }
                }
            }
        }
        LazyColumn(Modifier.weight(1f), state = listState) {
            item {
                Box(Modifier.fillMaxWidth().padding(vertical = 4.dp), contentAlignment = Alignment.Center) {
                    if (reachedStart) Text(if (group != null) "This is the beginning of this group" else "This is the beginning of your conversation with ${peerName}", color = Color.White.copy(alpha = 0.4f),
                        style = MaterialTheme.typography.labelSmall)
                    // Offered once the window is full: a short conversation is already all there.
                    else if (all.size >= HistoryWindow.PAGE) TextButton(onClick = { loadOlder() }) { Text("Load older messages", color = SkAccent) }
                }
            }
            itemsIndexed(all) { i, m ->
                when (RowKind.of(m.isSystem, m.isUndecryptable)) {
                    // A security notice about this contact, kept in the conversation itself.
                    RowKind.SYSTEM -> {
                        io.skwod.app.SecurityNotices.systemRow(m.content ?: "") { id ->
                            if (group != null) model.groups.shown(id, group).label else if (id == dm.peerUserId) peerName else "A member (${id.take(6)}…)" }
                            // "View safety number" on a row about this contact's devices.
                            ?.let { SystemRow(it, m.createdAt, onAction = if (group == null) ({ showVerify = true }) else null) }
                        return@itemsIndexed
                    }
                    // A message this device could not decrypt: a muted stand-in, replaced in
                    // place when its author's device sends it again.
                    RowKind.UNDECRYPTABLE -> {
                        val info = try { uniffi.skwod_core.undecryptablePlaceholder(m) } catch (_: Exception) { null }
                        UndecryptableRowView(UndecryptableRow.text(info?.isFinal ?: true, shownAuthor(info?.fromUserId ?: m.authorId).label), m.createdAt)
                        return@itemsIndexed
                    }
                    RowKind.MESSAGE -> {}
                }
                val mine = m.authorId == "__me__" || (m.authorId != null && m.authorId == model.session?.userId)
                val grouped = i > 0 && all[i - 1].authorId == m.authorId && !all[i - 1].isSystem && !all[i - 1].isUndecryptable
                // My rows use my userId; the rest are the peer — or, in a group, whoever wrote the row.
                val authorId = if (mine) model.session?.userId else if (group != null) m.authorId else dm.peerUserId
                val rowShown = shownAuthor(authorId)
                val rowName = if (group != null) rowShown.name else peerName
                // The same menu a channel message has: react, reply, edit and delete (for
                // everyone) — sealed to every device of both people, like the message itself.
                val actions = MessageActions(
                    onReact = { emoji ->
                        val already = reactionsByMsg[m.messageId]?.firstOrNull { it.emoji == emoji }?.mine ?: false
                        queue("Couldn't change the reaction — try again.") { c -> c.queueDmReaction(dm.conversationId, peers, m.messageId, emoji, already) }
                    },
                    onReply = { editing = null; replyingTo = m },
                    onEdit = { replyingTo = null; editing = m; draft = ChatTags.parse(m.content ?: "").text },
                    onForward = null,
                    onDelete = { queue("Couldn't delete that message — try again.") { c -> c.queueDmDelete(dm.conversationId, peers, m.messageId) } },
                    onReport = authorId?.let { id -> { reporting = SafetyTarget(id, rowName, ChatTags.parse(m.content ?: "").text.ifBlank { null }) } },
                    onBlock = authorId?.let { id -> { blocking = SafetyTarget(id, rowName) } },
                    onRetry = { Outbox.retry(model, it) },
                    onDiscard = { Outbox.discard(model, it, scopeName, m.messageId) },
                )
                // A reply quotes only what this conversation's two participants wrote: never a
                // system row, never a row some other account got filed under this conversation id.
                val replyPreview = m.replyToId?.let { id -> all.firstOrNull { it.messageId == id } }
                    ?.takeIf { p -> !p.isSystem && !p.isUndecryptable &&
                        (if (group != null) DmReplyPolicy.quotable(p.authorId, p.isDeleted, me, group.others) else DmReplyPolicy.quotable(p.authorId, p.isDeleted, me, dm.peerUserId)) }
                    ?.let { p -> "${if (DmReplyPolicy.mine(p.authorId, me)) "you" else shownAuthor(p.authorId).name}: ${ChatTags.parse(p.content ?: "").text.take(60)}" }
                // A mention of me (or, in a group, a reply to me) is highlighted like in a channel.
                val replyToMine = group != null && m.replyToId?.let { id -> all.firstOrNull { it.messageId == id }?.authorId }?.let { DmReplyPolicy.mine(it, me) } == true
                val mentionsMe = !mine && Mentions.mentionsMe(ChatTags.parse(m.content ?: "").mentions, me, m.authorId,
                    everyoneHonoured = false, replyToMine = replyToMine)
                MessageRow(if (mine) "you" else rowName, m.content ?: "", mine, m.createdAt, grouped, authorId,
                    isEdited = m.isEdited, isDeleted = m.isDeleted, replyPreview = replyPreview,
                    reactions = reactionsByMsg[m.messageId] ?: emptyList(), actions = actions,
                    nameTrust = if (mine) null else rowShown, sendState = if (mine) sendStates[m.messageId] else null,
                    mentionsMe = mentionsMe, mentionName = mentionName)
            }
        }
        // Replying to / editing a message: say so, with a way out.
        (editing ?: replyingTo)?.let { target ->
            Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(if (editing != null) "Editing message" else "Replying: ${ChatTags.parse(target.content ?: "").text.take(60)}",
                    color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1f))
                TextButton(onClick = { if (editing != null) draft = ""; editing = null; replyingTo = null }) { Text("Cancel", color = SkAccent) }
            }
        }
        // While sends are held (or a device nobody vouched for is listed): what happened, what it
        // means, and the two ways forward.
        if (hold != IdentityHold.Banner.NONE) {
            val amber = Color(0xFFFFA726)
            Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)
                .background(amber.copy(alpha = 0.10f), RoundedCornerShape(12.dp))
                .border(1.dp, amber.copy(alpha = 0.35f), RoundedCornerShape(12.dp)).padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.GppMaybe, null, tint = amber, modifier = Modifier.size(18.dp)); Spacer(Modifier.width(6.dp))
                    Text(IdentityHold.title(hold, peerName), color = amber, style = MaterialTheme.typography.titleSmall)
                }
                Spacer(Modifier.height(6.dp))
                Text(IdentityHold.body(hold, peerName, wasVerified = status?.sendsHeld == true),
                    color = Color.White.copy(alpha = 0.75f), style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Button(onClick = { showVerify = true }) { Text("Verify") }
                    Spacer(Modifier.width(8.dp))
                    OutlinedButton(enabled = !accepting, onClick = {
                        accepting = true
                        scope.launch {
                            // Continue without verifying: accept the devices listed now (the
                            // contact becomes unverified), then send again what was not delivered.
                            val c = model.client
                            // Exactly the set the banner was drawn for (audit L2).
                            val shown = status?.acceptFingerprint ?: ""
                            var changed = false
                            val ok = c != null && try { withContext(Dispatchers.IO) { c.acceptIdentityChange(dm.peerUserId, "", shown) }; true }
                                catch (e: uniffi.skwod_core.CoreException.IdentityChanged) { changed = true; false }
                                catch (e: Exception) { model.routeIfDeviceError(e); false }
                            if (!ok) error = if (changed) "Their devices changed again while you were deciding. Check the banner and decide again."
                                else "Couldn't accept the change — try again."
                            refreshStatus()
                            accepting = false
                            if (ok) {
                                error = null; failedHeld = false
                                Outbox.retryAll(model, IdentityHold.toRetry(sendStates))
                                if (draft.isNotBlank()) sendDraft()
                            }
                        }
                    }) { Text(if (draft.isBlank()) "Accept" else "Accept & send") }
                    if (accepting) { Spacer(Modifier.width(8.dp)); CircularProgressIndicator(Modifier.size(18.dp), color = SkAccent) }
                }
            }
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(4.dp)) }
        if (dm.isSplit) {
            Text("This arrived inside a conversation that belongs to someone else, so Skwod keeps it apart and you can't reply here. To write to this person, start a new chat with them.",
                color = Color(0xFFFFA726), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(8.dp))
        } else {
        // Typing "@…": this conversation's other people whose names match, to insert as a mention.
        MentionSuggestions(draft,
            candidates = (group?.others ?: listOf(dm.peerUserId)).filter { it.isNotEmpty() && it != me && !model.isBlockedUser(it) }
                .map { it to shownAuthor(it) },
            onPick = { uid, label -> draft = Mentions.complete(draft, label); mentionPicks.add(uid to label) })
        // Only this conversation's other people can show as typing here.
        TypingLine(scopeName, accept = { uid -> if (group != null) uid in group.others else uid == dm.peerUserId },
            nameOf = { uid -> shownAuthor(uid).label })
        pasted?.let { p -> PastedImagePreview(p, onRemove = { pasted = null }) }
            ?: run { if (clipHasImage && !uploading && editing == null) PasteImageChip {
                // Tagged with the conversation it started in: a picture read after a switch is dropped.
                val startedFor = dm.conversationId
                scope.launch {
                    val result = try { Result.success(ComposerPaste.take(ctx, model)) } catch (e: AttachmentException) { Result.failure(e) }
                    if (!StagingRule.belongs(startedFor, onScreen)) return@launch
                    result.onSuccess { pasted = it; error = null }.onFailure { error = it.message }
                }
            } }
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { picker.launch("*/*") }, enabled = !uploading) {
                if (uploading) CircularProgressIndicator(Modifier.size(22.dp), color = SkAccent)
                else Icon(Icons.Filled.AddCircle, "Attach", tint = SkAccent)
            }
            IconButton(onClick = { showMusic = true }) { Icon(Icons.Filled.MusicNote, "Share a song", tint = SkAccent) }
            OutlinedTextField(draft, { draft = it; announceTyping(it) }, placeholder = { Text("Encrypted message…", color = Color.White.copy(alpha = 0.4f)) },
                modifier = Modifier.weight(1f), singleLine = false, maxLines = 4,
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
                    sendFile { Uploads.prepareImage(ctx, model, pic.bytes, forDm = true) }
                }
                sendDraft()
            }, enabled = !sending && (draft.isNotBlank() || (pasted != null && editing == null && !uploading)), shape = RoundedCornerShape(50)) {
                Icon(Icons.Filled.ArrowUpward, "Send", tint = Color.Black)
            }
        }
        }
    }
}

