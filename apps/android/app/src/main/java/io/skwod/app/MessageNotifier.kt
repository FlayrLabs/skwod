package io.skwod.app

import android.content.Context
import java.util.concurrent.ConcurrentHashMap

/**
 * Turns "something arrived" into a local notification — after decrypting it ON THIS DEVICE.
 *
 * The realtime socket only says that a message exists (ciphertext); the engine fetches and
 * decrypts it, and this class decides what to show. With "Hide message content" on, or when
 * nothing could be decrypted, the notification is the generic "New message". Nothing readable is
 * ever logged. With app lock or "Hide message content" on, the generic form is all that is ever
 * posted, so it is all a lock screen can show; with both off, Android's own lock-screen setting
 * decides whether the text or the generic public version is shown (see [Notifications.message]).
 *
 * What was announced is remembered by MESSAGE ID, per skwod and across restarts
 * ([AnnouncedLedger]) — never decided by the server's timestamp alone.
 */
class MessageNotifier(private val model: AppModel, private val ctx: Context) {
    companion object {
        /** The preferences this keeps its "seen until" marks in (deleted per skwod: [LocalData.forgetItems]). */
        const val PREFS = "skwod-notify"
    }

    private val notified = ConcurrentHashMap.newKeySet<String>()
    private val names = ConcurrentHashMap<String, String>()        // userId → username
    private val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    @Volatile private var since = System.currentTimeMillis()

    /**
     * A workspace was (re)opened. Messages newer than the last moment the user had the app in
     * front (kept across restarts — a timestamp only) are still owed a notification; nothing
     * older than that, and never more than a day back.
     */
    fun reset() {
        notified.clear(); names.clear(); invited.clear()
        val now = System.currentTimeMillis()
        val saved = prefs.getLong(LocalData.seenAtName(model.current?.id ?: ""), now)
        since = saved.coerceIn(now - 24L * 60 * 60 * 1000, now)
    }

    /** The user is looking at the app (or just left it): everything so far counts as seen. */
    fun markSeen() {
        since = System.currentTimeMillis()
        model.current?.id?.let { prefs.edit().putLong(LocalData.seenAtName(it), since).apply() }
    }

    /**
     * Whether a decrypted body is announced. The core owns the rule (`messageNotifies`: false for
     * game, like, comment, avatar, addr and sys bodies); [NotifyPolicy] is the same rule in
     * Kotlin, used if the core cannot be asked.
     */
    private fun coreNotifies(body: String): Boolean =
        try { uniffi.skwod_core.messageNotifies(body) } catch (_: Throwable) { NotifyPolicy.notifies(body) }

    private fun owed(m: uniffi.skwod_core.Message, me: String): Boolean =
        NotifyPolicy.shouldNotify(m.content, m.authorId, me, m.isDeleted,
            isSystem = m.isSystem, isUndecryptable = m.isUndecryptable, isBlocked = model::isBlockedUser, coreNotifies = ::coreNotifies) &&
            (m.content == null || NotifyPolicy.preview(m.content!!) != null)

    /**
     * After the socket (re)connects — a reboot, Doze, a network change, the host coming back —
     * announce what arrived in the meantime: one notification per channel (the newest message,
     * or a count), plus any direct messages.
     */
    suspend fun catchUp() {
        if (model.realtime.appActive) return
        val c = model.client ?: return
        val me = model.current?.userId ?: return
        if (model.baseUrl == null) return
        val generic = quiet()
        val asked = model.bound ?: return
        val ledger = ledger() ?: return
        for (space in model.chat.spaces.toList().take(30)) {
            val rows = try { c.fetchChannelMessages(space.channelId, me) } catch (_: Exception) { continue }
            // Fetched for the workspace that was asked: nothing of it is announced after a switch.
            if (model.bound !== asked) return
            // `since` is only a floor (nothing older than what the user saw). Whether a message
            // was announced is decided by its ID, kept across restarts: a message the server
            // dated in the future passes the floor every time, and is still announced once.
            val fresh = rows.filter { m -> m.createdAt > since && owed(m, me) }.filter { m -> ledger.announce(m.messageId, sure = m.content != null) }
            if (fresh.isEmpty()) continue
            // Stored before it is posted: a process killed in between announces nothing twice.
            saveLedger(ledger)
            val last = fresh.last()
            val text = last.content?.let { NotifyPolicy.preview(it) }
            val topic = "channel:${space.channelId}"
            when {
                generic || text == null -> post(topic, if (generic) "Skwod" else "#${space.channelName}",
                    if (fresh.size == 1) "New message" else "${fresh.size} new messages")
                else -> {
                    val who = nameOf(last.authorId, space.serverId)?.let { model.contacts.shown(last.authorId, it).label } ?: "Someone"
                    val more = if (fresh.size > 1) " (+${fresh.size - 1} more)" else ""
                    post(topic, "#${space.channelName} · ${space.name}", "$who: $text$more")
                }
            }
        }
        saveLedger(ledger)
        // Fetching channels may have drained the mailbox too.
        model.syncDmsNow()
    }

    private suspend fun nameOf(userId: String?, serverId: String?): String? {
        if (userId == null) return null
        names[userId]?.let { return it }
        val c = model.client ?: return null
        if (serverId != null) {
            try { c.listMembers(serverId).forEach { names[it.userId] = it.username } } catch (_: Exception) {}
        }
        return names[userId]
    }

    /**
     * A `message` event for a channel we are in. The event says nothing about what the message
     * IS — it may be a like, a comment, an avatar, a game move — so nothing is announced until
     * this exact message has been fetched, decrypted and found to be real chat from someone
     * else. A message that cannot be found is not announced at all (no phantom "New message").
     */
    suspend fun channelMessage(channelId: String, messageId: String) {
        val c = model.client ?: return
        val me = model.current?.userId ?: return
        val space = model.chat.spaces.firstOrNull { it.channelId == channelId } ?: return
        if (messageId.isEmpty()) return
        val topic = "channel:$channelId"
        val asked = model.bound
        val rows = try { c.fetchChannelMessages(channelId, me) } catch (_: Exception) { emptyList() }
        // Fetched for the workspace that was active when it was asked: not announced (under
        // another workspace's names) after a switch.
        if (asked == null || model.bound !== asked) return
        model.drainDmEvents()                       // that fetch may have drained the mailbox
        // Game moves are filed out of the chat history by the core, and anything else that is
        // not in the window is not chat this device can show: either way, silence.
        val m = rows.lastOrNull { it.messageId == messageId } ?: return
        if (!owed(m, me)) return
        val ledger = ledger() ?: return
        val first = ledger.announce(m.messageId, sure = m.content != null)
        saveLedger(ledger)
        if (!first) return
        val text = m.content?.let { NotifyPolicy.preview(it) }
        // A mention of me (or an honoured @everyone, or a reply to me) alerts even where muted.
        val decoded = ChatTags.parse(m.content ?: "").mentions
        // @everyone from the pinned owner or an admin ([Mentions.everyoneSenders]).
        val everyone = if (decoded.everyone) model.refreshEveryoneSenders(space.serverId) else emptySet()
        if (asked !== model.bound) return
        val replyToMine = m.replyToId?.let { id -> rows.firstOrNull { it.messageId == id }?.authorId }?.let { it == me || it == "__me__" } == true
        val mentioned = Mentions.mentionsMe(decoded, me, m.authorId,
            everyoneHonoured = Mentions.everyoneHonoured(m.authorId, everyone), replyToMine = replyToMine)
        if (mentioned) model.addMentionBadges(listOf(m.messageId), topic)
        if (quiet()) { post(topic, if (mentioned) MentionAlert.title("", "", redacted = true) else "Skwod", "New message", mentioned); return }
        val who = nameOf(m.authorId, space.serverId)?.let { model.contacts.shown(m.authorId, it).label } ?: "Someone"
        if (mentioned) { post(topic, MentionAlert.title(who, "#${space.channelName}", redacted = false), text ?: "New message", mentioned = true); return }
        if (text == null) { post(topic, "#${space.channelName}", "New message"); return }
        post(topic, "#${space.channelName} · ${space.name}", "$who: $text")
    }

    /**
     * Direct messages the core just filed ([uniffi.skwod_core.DmEvent]): announce each one that
     * came from the other person. A copy of something we sent from another of our devices
     * (`fromSelf`) is listed but never announced.
     */
    fun dmEvents(all: List<uniffi.skwod_core.DmEvent>) {
        val generic = quiet()
        // The caller filters too ([AppModel.handleDmEvents]); the rule is applied here as well so
        // no path into this function can announce someone this account blocked.
        val events = NotifyPolicy.withoutBlocked(all, { it.peerUserId }, model::isBlockedUser)
        val ledger = ledger() ?: return
        try { for (e in events) {
            if (e.fromSelf) { ledger.skip(e.messageId); continue }
            if (e.createdAt < since - 60_000) { ledger.skip(e.messageId); continue }
            if (!NotifyPolicy.notifies(e.text) || !coreNotifies(e.text)) continue
            val text = NotifyPolicy.preview(e.text) ?: continue
            if (!ledger.announce(e.messageId, sure = true)) continue
            val topic = "dm:${e.conversationId}"
            if (model.realtime.appActive && model.realtime.focusedTopic == topic) continue
            // Named through the contact book: an unverified sender is announced as such, and a
            // name that imitates someone the user knows is never shown as that person.
            val claimed = model.chat.dms.firstOrNull { it.conversationId == e.conversationId && it.peerUserId == e.peerUserId }?.name
            val who = model.contacts.shown(e.peerUserId, claimed).label
            // A group message is announced under the group's title, with who wrote it.
            val group = model.groups.find(e.conversationId)
            // In a group, a mention of me alerts even where muted (no @everyone in DMs).
            val mentioned = group != null && model.current?.userId?.let { me ->
                Mentions.mentionsMe(Mentions.decode(e.text), me, e.peerUserId, everyoneHonoured = false) } == true
            if (mentioned) model.addMentionBadges(listOf(e.messageId), topic)
            when {
                generic -> post(topic, if (mentioned) MentionAlert.title("", "", redacted = true) else "Skwod", "New message", mentioned)
                mentioned -> post(topic, MentionAlert.title(who, model.groups.title(group!!), redacted = false), text, mentioned = true)
                group != null -> post(topic, model.groups.title(group), "$who: $text")
                else -> post(topic, who, text)
            }
        } } finally { saveLedger(ledger) }
    }

    /**
     * Previews are off — by the user's setting, or because app lock is ENABLED. The persisted
     * setting decides, never the in-memory "locked right now": an unlocked app in the
     * background, or a process started by the connection service with no UI, must not show
     * who wrote what on a phone whose owner asked for a lock. ([Notifications.message] applies
     * the same rule again as the last gate.)
     */
    private fun quiet(): Boolean = NotifyPolicy.redacted(model.settings.hideMessageContent, model.settings.appLock, AppLock.locked)

    /**
     * One message that passed every content rule: what it does here is [AlertPolicy]'s
     * decision — nothing for the chat on screen or under Do Not Disturb, the app's own sound
     * with a silent notification in front, a notification with sound otherwise.
     */
    private fun post(topic: String, title: String, text: String, mentioned: Boolean = false) {
        val active = model.realtime.appActive
        val out = AlertPolicy.received(AlertPolicy.Incoming(
            // A mention of me alerts through a muted chat; only a muted skwod silences it.
            muted = MentionAlert.muted(model.muteHolds(topic), model.muteHolds(MuteList.SKWOD), mentioned),
            doNotDisturb = model.myStatus == "dnd",
            appActive = active,
            onScreen = active && model.realtime.focusedTopic == topic,
            soundOn = model.settings.soundReceived,
            lastSoundAt = Sounds.lastReceivedAt,
            now = System.currentTimeMillis()))
        if (out.inAppSound) Sounds.play(ctx, Sounds.RECEIVED)
        if (out.banner) Notifications.message(ctx, topic, title, text, NotifyPolicy.Text.PERSONAL, silent = !out.bannerSound)
    }

    private val invited = ConcurrentHashMap.newKeySet<String>()

    // ---- which messages were announced: by id, per skwod, kept across restarts ----

    private fun ledgerKey(workspaceId: String) = LocalData.announcedName(workspaceId)
    private var ledgerFor: String? = null
    private var ledgerRef = AnnouncedLedger()

    /**
     * The active skwod's ledger (each skwod has its own: message ids are a server's choice, and
     * one server must not be able to silence another's). Kept with the other per-skwod items in
     * the encrypted store. If the store cannot be read right now the ledger is in memory only
     * for the moment — it is never written over what could not be read.
     */
    @Synchronized private fun ledger(): AnnouncedLedger? {
        val wid = model.current?.id ?: return null
        if (ledgerFor == wid) return ledgerRef
        val stored = try { model.secretRead(ledgerKey(wid)) } catch (_: Exception) { return unreadLedgers.getOrPut(wid) { AnnouncedLedger() } }
        ledgerRef = AnnouncedLedger.decode(stored); ledgerFor = wid
        return ledgerRef
    }
    private val unreadLedgers = ConcurrentHashMap<String, AnnouncedLedger>()

    @Synchronized private fun saveLedger(ledger: AnnouncedLedger) {
        val wid = ledgerFor ?: return
        if (ledger === ledgerRef && ledger.dirty) model.secretPut(ledgerKey(wid), ledger.encode())
    }

    /** A skwod's local data is deleted: what was announced in it goes too. */
    @Synchronized fun forget(workspaceId: String) {
        if (ledgerFor == workspaceId) { ledgerFor = null; ledgerRef = AnnouncedLedger() }
        unreadLedgers.remove(workspaceId)
        model.secretPut(ledgerKey(workspaceId), null)
    }

    /**
     * A message arrived in a group this device has not accepted. Nothing of it is shown — not
     * who wrote it, not what it says: one generic notice per conversation that there is an
     * invitation to look at.
     */
    fun groupInvitation(conversationId: String) {
        if (!invited.add(conversationId)) return
        if (model.realtime.appActive) return           // in front: the DM list shows the invitation
        Notifications.message(ctx, "group-invite:$conversationId", GroupRules.INVITATION_TITLE, GroupRules.INVITATION_NOTICE, NotifyPolicy.Text.FIXED)
    }

    /** Something about the account that needs the user (a restore waiting for an answer). */
    fun account(id: String, title: String, body: String) {
        Notifications.message(ctx, "account:$id", if (quiet()) "Skwod" else title, if (quiet()) "Your account needs your attention. Open Skwod." else body, NotifyPolicy.Text.FIXED)
    }

    /** Someone is waiting for me to let them into a server (realtime `join_request`). */
    fun joinRequest(serverId: String, pending: Int) {
        if (model.realtime.appActive) return           // in front: the badge on the members button says it
        val space = model.chat.spaces.firstOrNull { it.serverId == serverId }
        val where = if (quiet() || space == null) "a server" else space.name
        Notifications.message(ctx, "join:$serverId", "Skwod",
            if (pending > 1) "$pending people are waiting to join $where." else "Someone is waiting to join $where.", NotifyPolicy.Text.FIXED)
    }

    /** Someone started a call in a server we are in. */
    suspend fun ring(ring: Ring, workspace: Workspace? = null) {
        if (CallState.active.value || model.callOpening || model.answeredCallServer != null) return      // already in (or entering) a call
        val now = System.currentTimeMillis()
        // A ring past its deadline is over (a replay after a late wake, a stale list): show nothing.
        if (!RingPolicy.isLive(ring.expiresAt, now)) return
        if (ring.ringId.isNotEmpty() && model.incomingCall?.ringId == ring.ringId) return   // already ringing (replay)
        if (model.incomingCall != null) return                   // one ring at a time; a second never replaces it
        // A ring on ANOTHER skwod than the one on screen is only labelled with that skwod: its
        // member names belong to an engine that is not open, and nothing is switched unless
        // the user answers.
        val elsewhere = workspace != null && workspace.localId != model.current?.localId
        val label = if (elsewhere) "Call on ${workspace!!.displayName}" else {
            val space = model.chat.spaces.firstOrNull { it.serverId == ring.serverId }
            val who = nameOf(ring.fromUserId, ring.serverId)?.let { model.contacts.shown(ring.fromUserId, it).label }
            when {
                who != null && space != null -> "$who · ${space.name}"
                who != null -> who
                else -> space?.name ?: "Skwod call"
            }
        }
        // The server's `expires_at` can end the ring early; it can never extend it past the
        // app's own ring duration.
        val ringFor = RingPolicy.ringFor(ring.expiresAt, System.currentTimeMillis(), Notifications.RING_TIMEOUT_MS)
        if (ringFor <= 0) return
        // With app lock on, neither the notification nor the call screen (which shows over the
        // keyguard) says who is calling.
        val call = IncomingCall(ring.serverId, ring.channelId, NotifyPolicy.callLabel(label, model.settings.appLock), ring.ringId, ring.expiresAt, workspace?.localId ?: "")
        model.incomingCall = call
        Notifications.incomingCall(ctx, ring.serverId, call.callerName, ringFor)
        kotlinx.coroutines.delay(ringFor)
        if (model.incomingCall === call) { model.incomingCall = null; Notifications.cancelIncomingCall(ctx) }
    }

    /** `ring_cancel`: the caller hung up, or the call was answered elsewhere. */
    fun ringCancelled(channelId: String, ringId: String?, serverId: String?) {
        val call = model.incomingCall ?: return
        val current = Ring(call.serverId, call.channelId, "", call.ringId, call.expiresAt)
        if (!RingPolicy.cancels(current, channelId, ringId, serverId)) return
        model.incomingCall = null
        Notifications.cancelIncomingCall(ctx)
    }
}
