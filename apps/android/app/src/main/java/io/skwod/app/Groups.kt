package io.skwod.app

import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Group DMs (3–10 people) of the active workspace: every message sealed separately to every
 * device of every member, no shared group key.
 *
 * WHO IS IN A GROUP is decided on this device, once: the people the user picked when starting
 * it, or the people shown when they accepted it. That set is stored here (in the encrypted
 * cache) and is the only set messages are sealed to. The server's listing of a conversation is
 * never adopted — a server that adds someone to a conversation would otherwise get every member
 * to encrypt to its ghost. A listing that differs is flagged and ignored
 * ([GroupRules.reconcile]); a group this device has never seen is an INVITATION the user
 * accepts (seeing its members) or not; and changing who is in a group means starting a new one.
 *
 * A group has no name of its own: its title is its members as the contact book shows them.
 * Same structure as the Apple app's `GroupDMs.swift`.
 */
class GroupDms(private val model: AppModel) {
    /** Groups this device created or accepted, most recently active first. Member sets are fixed. */
    val list = mutableStateListOf<GroupConversation>()
    /** Conversations the server lists that this device has not accepted. */
    val invitations = mutableStateListOf<GroupConversation>()
    /** Bumped when either list changed. */
    val revision = mutableIntStateOf(0)
    /** A saved list was lost as a whole and the user has not said they have seen it ([ConversationStore.clearReview]). */
    val reviewPending = androidx.compose.runtime.mutableStateOf(false)
    /** Groups the user said to ignore (ids are all this device keeps of them). */
    val ignored = mutableStateListOf<String>()
    /** How many times in a row the conversations could not be read. */
    val loadFailures = mutableIntStateOf(0)

    /** The store's other state changed ([ConversationStore.Listener.state]). */
    fun state(pending: Boolean, ignoredIds: Set<String>, failures: Int) {
        if (reviewPending.value != pending) reviewPending.value = pending
        val sorted = ignoredIds.sorted()
        if (ignored.toList() != sorted) { ignored.clear(); ignored.addAll(sorted) }
        if (loadFailures.intValue != failures) loadFailures.intValue = failures
    }

    /** "Stop ignoring": the id is free again; if the server still lists the group it comes back as an invitation. */
    suspend fun unignore(conversationId: String) { if (store?.unignore(conversationId) == true) refresh() }

    /** The user has seen that a saved list was lost: listed conversations are added again. */
    suspend fun clearReview() { store?.clearReview(); model.refreshDmList() }

    /** "Try again" when the conversations could not be read. */
    suspend fun retryLoad() { if (load()) { model.refreshDmList(); refresh() } }

    private val store: ConversationStore? get() = model.chat.store

    /** The store's lists changed ([ConversationStore.Listener.changed]): show them. */
    fun published(groups: List<GroupConversation>, invites: List<GroupConversation>) {
        var touched = false
        if (list.toList() != groups) { list.clear(); list.addAll(groups); touched = true }
        if (invitations.toList() != invites) { invitations.clear(); invitations.addAll(invites); touched = true }
        if (!touched) return
        revision.intValue++
        // The open group shows the "server disagrees" flag as soon as it is known.
        (model.chat.selection as? SidebarItem.Group)?.let { sel -> groups.firstOrNull { it.conversationId == sel.group.conversationId }?.let { if (it != sel.group) model.chat.selection = SidebarItem.Group(it) } }
    }

    /**
     * Put a store's notice in the Security activity of ITS workspace ([origin]). The store says
     * each one once per launch, and never again once this reports the row stored.
     */
    fun say(notice: ConversationStore.Notice, origin: ConversationStore) {
        val now = System.currentTimeMillis()
        model.launchIO {
            val stored = when (notice) {
                is ConversationStore.Notice.Conflict -> model.account.log("conversation_conflict", GroupRules.CONFLICT_TITLE, GroupRules.CONFLICT_MESSAGE, now, origin.tag)
                is ConversationStore.Notice.Outsider -> model.account.log("group_outsider", GroupRules.OUTSIDER_TITLE,
                    GroupRules.outsiderMessage(origin.findGroup(notice.conversationId)?.let(::title) ?: "a group"), now, origin.tag)
                is ConversationStore.Notice.OtherPeer -> model.account.log("conversation_peer_conflict", GroupRules.CONFLICT_TITLE, GroupRules.PEER_CONFLICT_MESSAGE, now, origin.tag)
                is ConversationStore.Notice.Duplicates -> model.account.log("conversation_duplicates", GroupRules.DUPLICATES_TITLE, GroupRules.duplicatesMessage(notice.keptAs), now, origin.tag)
                is ConversationStore.Notice.Unreadable -> model.account.log("conversation_list_unreadable", GroupRules.UNREADABLE_TITLE,
                    GroupRules.unreadableMessage(notice.list, notice.keptAs), now, origin.tag)
            }
            // Remembered as said only once its row is actually in Security activity.
            if (stored) origin.stored(notice)
        }
    }

    /**
     * Someone who is not in [group] as this device holds it sent something to it. It was
     * dropped; say so once per conversation, in Security activity.
     */
    fun outsiderDropped(group: GroupConversation) { store?.notice(ConversationStore.Notice.Outsider(group.conversationId)) }

    fun reset() { list.clear(); invitations.clear(); ignored.clear(); reviewPending.value = false; loadFailures.intValue = 0; revision.intValue++ }

    fun isGroup(conversationId: String): Boolean = find(conversationId) != null
    fun find(conversationId: String): GroupConversation? = store?.findGroup(conversationId)

    /**
     * The server described [conversationId] both as a direct conversation and as a group (or an
     * action of the user's would have put it in both stores). NOTHING is changed by this: the
     * store that claimed the id first keeps it ([GroupRules.mayClaim]). Said once per conversation.
     */
    fun noteConflict(conversationId: String) { store?.notice(ConversationStore.Notice.Conflict(conversationId)) }

    /**
     * What a DM event's conversation is to this device ([GroupRules.route]): an accepted group
     * routes as the group, a held direct conversation as direct. Read-only — a clash is noted
     * and changes neither store. UNKNOWN until both stores are read.
     */
    fun route(conversationId: String): GroupRules.Route = store?.route(conversationId) ?: GroupRules.Route.UNKNOWN

    /** Both stores, from the encrypted cache. False = they could not be read (nothing is decided then). */
    suspend fun load(): Boolean = store?.load() ?: false

    /**
     * Names this device has heard for people (claims), to show an invitation's members with —
     * in the workspace [origin] belongs to. Asked for AFTER a listing came back: if the user is
     * in another workspace by then, nothing is answered — not even a claimed name crosses from
     * one workspace into another.
     */
    fun hints(origin: ConversationStore): Map<String, String> = model.chat.ifCurrent(origin) {
        val out = HashMap<String, String>(model.contacts.roster)
        for (d in origin.dms) if (d.name.isNotEmpty()) out[d.peerUserId] = d.name
        out
    } ?: emptyMap()

    /**
     * Ask which group conversations the server lists for this account, and fold that in:
     * accepted groups KEEP their members (a differing listing is only flagged), conversations
     * this device has not accepted become invitations. Returns false when it could not be asked.
     */
    suspend fun refresh(): Boolean = store?.let { s -> s.refreshGroups { hints(s) } } ?: false

    /** Messages arrived in these groups: they move to the top of the list. */
    fun touched(conversationIds: List<String>) { store?.touchGroups(conversationIds) }

    /** One member as this device names them (contact-book rules). */
    fun shown(userId: String, group: GroupConversation? = null): ContactTrust.Shown = model.contacts.shown(userId, group?.claimedNames?.get(userId) ?: claimed(userId))

    private fun claimed(userId: String): String? =
        model.chat.dms.firstOrNull { it.peerUserId == userId }?.name?.takeIf { it.isNotEmpty() } ?: model.contacts.claimedName(userId)

    fun title(group: GroupConversation): String = GroupRules.title(group.others.map { shown(it, group).label })

    /**
     * Start (or reopen) the group with exactly these people. The member set is the one the USER
     * just picked, and stays that. Reopening a conversation this device already holds never
     * changes its stored set; an id the 1:1 store claims, or a group with other people holds,
     * is refused ([ConversationStore.openGroup]).
     */
    suspend fun open(others: List<String>): GroupConversation {
        // What is current is captured before the server is asked for the group's id
        // ([StoreTicket]): the group is started in THAT workspace's store, and handed back (to
        // be shown) only if it is still the current one when the answer comes.
        val ticket = model.chat.ticket() ?: throw IllegalStateException("Not connected — try again in a moment.")
        val group = ticket.store.openGroup(others) { hints(ticket.store) }
        if (!model.chat.holds(ticket)) throw IllegalStateException("You switched skwods while the group was being started — it is in the skwod you started it in.")
        return group
    }

    /** "Join group": store the invitation with EXACTLY the members that were shown. */
    fun accept(invitation: GroupConversation): GroupConversation? = store?.accept(invitation)

    /** "Join group" for the dialog: [invitation] must be the one ON SCREEN ([ConversationStore.join]). */
    fun join(invitation: GroupConversation): ConversationStore.Joined = store?.join(invitation) ?: ConversationStore.Joined.Refused

    /** "Ignore this group": remembered; the conversation is not listed again on this device. */
    fun decline(invitation: GroupConversation) { store?.decline(invitation) }
}
