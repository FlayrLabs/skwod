package io.skwod.app

/**
 * Build 44b, the app's half: what a row is, group conversations, uploads, the reports inbox.
 * Pure rules (no android.*, no FFI), unit-tested on the JVM.
 */

/** What a row of a conversation IS — recorded by the core when it wrote the row. */
enum class RowKind {
    /** Something a person sent. */
    MESSAGE,
    /** A notice the core wrote into the conversation ("X joined", "X added a device"). */
    SYSTEM,
    /** A message this device could not decrypt, standing in until its author sends it again. */
    UNDECRYPTABLE;

    companion object {
        /**
         * Decided by the row's FLAGS (`Message.isSystem`, `Message.isUndecryptable`), never by
         * its text or its author id. Any member can send a body that starts with
         * `\u0002skwod/sys|` or `\u0002skwod/undecryptable|`; the core stores such a body as
         * ordinary text with neither flag set, and it must be drawn as the plain message it is —
         * otherwise a member could forge "X joined" or hide a message behind a placeholder.
         */
        fun of(isSystem: Boolean, isUndecryptable: Boolean): RowKind = when {
            isUndecryptable -> UNDECRYPTABLE
            isSystem -> SYSTEM
            else -> MESSAGE
        }
    }
}

/** The muted row that stands in for a message this device could not decrypt. */
object UndecryptableRow {
    /** [authorName] = the display name of the placeholder's `fromUserId` as the contact book shows it. */
    fun text(isFinal: Boolean, authorName: String): String =
        if (isFinal) "Couldn't decrypt this message" else "Couldn't decrypt this message — asking $authorName to resend"

    /** It is not a message: it never counts as unread and never notifies. */
    const val COUNTS_AS_UNREAD = false
}

/**
 * A group conversation as THIS device holds it. [others] are its members other than this
 * account — the people the user picked when starting it, or the people shown when they accepted
 * it. That set is fixed from then on and is the only set a message is ever sealed to.
 * [claimedNames] are names as first heard (claims, shown through the contact book's rules).
 * [serverDisagrees]: the server now lists different people for this conversation; shown as a
 * warning, and the set is NOT changed.
 */
data class GroupConversation(val conversationId: String, val others: List<String>,
                             val claimedNames: Map<String, String> = emptyMap(), val serverDisagrees: Boolean = false,
                             /**
                              * Invitations only, never stored: this conversation may be a group the user HAD
                              * joined — the list that would say so could not be read ([ConversationStore.Review]).
                              * Shown as "review this group", not as a fresh invitation.
                              */
                             val needsReview: Boolean = false)

/** Group conversations: 3–10 people, so 2–9 others. */
object GroupRules {
    const val SERVER_DISAGREES = "The server now lists different people for this group than the ones you joined it with. Skwod ignores that: your messages go only to the people shown here."
    const val INVITATION_TITLE = "Group invitation"
    const val INVITATION_NOTICE = "You were added to a group. Open Skwod to see who is in it."
    const val JOIN_TITLE = "Join this group?"
    const val JOIN_BODY = "You were added to a group with the people below. If you join, your messages in it are sealed to exactly these people — nobody the server adds later."
    const val STORE_KEY = "sidebar.groups"
    const val DECLINED_KEY = "groups.declined"

    fun invitationLine(others: Int): String = "${others + 1} people · tap to see who"

    /** [conflicts]: conversation ids the server describes both as a direct conversation and as a group. */
    class Reconciled(val accepted: List<GroupConversation>, val invitations: List<GroupConversation>, val conflicts: List<String> = emptyList())

    const val CONFLICT_TITLE = "This conversation's server data conflicts"
    const val PEER_CONFLICT_MESSAGE = "The server described one of your direct conversations as being with a different account than the one you hold it with. Skwod kept it as it was and ignored the rest."
    const val INVITATION_CHANGED = "This invitation changed while you were looking at it. Nothing was joined — review who is in it again."
    const val IGNORED_GROUP_MESSAGE = "The server answered with a conversation id that is used by a group you ignored, so the chat was not opened. To use it, stop ignoring that group (Ignored groups, in your conversation list)."
    const val IGNORED_TITLE = "Ignored groups"
    const val IGNORED_BODY = "Nothing of these groups is shown on this phone, and their conversation ids cannot be used for anything else. If you stop ignoring one and the server still lists it, it comes back as an invitation."
    const val REVIEW_PENDING = "A saved list of your conversations could not be read (see Security activity). Until you continue, conversations the server lists are not added here, and every group it lists is shown as “Review this group”."
    const val LISTS_UNREADABLE = "Skwod could not read your conversations on this phone, so none are shown. Nothing was deleted."
    const val UNREADABLE_TITLE = "A saved list could not be read"
    fun unreadableMessage(list: String, keptAs: String): String =
        "The list of your $list that Skwod keeps on this phone could not be fully read. Skwod kept what it could read and continues with that. Nothing was deleted: the data as it was is kept on this phone (as “$keptAs”). A group you had joined may be shown as “Review this group” — check who is in it before joining again."
    const val DUPLICATES_TITLE = "Duplicate conversations were tidied"
    fun duplicatesMessage(keptAs: String): String =
        "An earlier version of Skwod had listed more than one account under the same direct conversation. Skwod now keeps one account per conversation — the one you started, or the first. Nothing was deleted: the list as it was is kept on this phone (as “$keptAs”)."
    const val REVIEW_TITLE = "Review this group"
    const val REVIEW_BODY = "Skwod could not read part of what it had saved about your groups on this phone, and this may be a group you had joined. These are the people the server lists in it NOW — they may not be the people you joined it with. If you join, your messages in it are sealed to exactly these people."
    const val CONFLICT_MESSAGE = "The server described one of your conversations in two different ways — as a direct conversation and as a group. Skwod kept it as it was and ignored the rest."

    /**
     * ONE rule for a conversation id that turns up both as a direct conversation and as a
     * group: ids are claimed locally, first come first served. Whichever store this device put
     * the id in first BY ITS OWN ACTION — adding or opening a DM; starting or accepting a
     * group — owns it. Nothing the server lists or delivers can create an entry for an id the
     * other store holds, and nothing it lists can delete or change a claimed entry. On a clash
     * neither store changes: the original owner keeps routing, the conflicting data is dropped,
     * and it is said once in Security activity. The user's own actions obey the same rule.
     */
    fun mayClaim(conversationId: String, heldByOtherStore: Collection<String>): Boolean = conversationId !in heldByOtherStore

    /**
     * Fold the server's listing into what this device holds — WITHOUT ever changing an accepted
     * group: not its members (a server that could add someone to a conversation's listing would
     * otherwise get every member to encrypt to its ghost), and not its existence. An accepted
     * group keeps its stored set whatever the listing says (a differing listing only sets the
     * flag; one missing from the listing is kept). A listed conversation this device has not
     * accepted is an INVITATION — unless this device holds that id as a direct conversation
     * ([direct]: the ids a direct conversation CLAIMS): then it is a conflict, and no
     * invitation. A declined one is left out. An id listed more than once makes one invitation
     * (its first listing); an accepted group is flagged if ANY of its listings differs.
     * [listed] members are the OTHERS (this account already removed).
     */
    fun reconcile(accepted: List<GroupConversation>, listed: List<Pair<String, List<String>>>, declined: Set<String>,
                  direct: Set<String> = emptySet(),
                  /** Ids that were DIRECT entries in a list that could not be fully read: never offered as a group. */
                  lostDirect: Set<String> = emptySet(),
                  /** Ids that were accepted GROUPS whose entry was lost: offered for review, never as a plain invitation. */
                  reviewGroups: Set<String> = emptySet(),
                  /** The groups list could not be read at all: everything listed and not accepted is for review. */
                  reviewAll: Boolean = false): Reconciled {
        val kept = accepted.toMutableList()
        val invitations = ArrayList<GroupConversation>()
        val conflicts = LinkedHashSet<String>()
        val flagged = HashSet<String>()
        for ((id, members) in listed) {
            val others = members.filter { it.isNotEmpty() }.distinct()
            val i = kept.indexOfFirst { it.conversationId == id }
            if (i >= 0) {
                if (kept[i].others.toSet() != others.toSet()) flagged += id
                kept[i] = kept[i].copy(serverDisagrees = id in flagged)
            }
            else if (!mayClaim(id, direct)) conflicts += id
            else if (id in lostDirect) continue
            else if (id !in declined && canStart(others.size) && invitations.none { it.conversationId == id })
                invitations += GroupConversation(id, others, needsReview = reviewAll || id in reviewGroups)
        }
        return Reconciled(kept, invitations, conflicts.toList())
    }

    /** What a DM event's conversation is, as far as this device knows. */
    enum class Route {
        /** A group this device created or accepted: the event updates that group. */
        GROUP,
        /** A group this device has not accepted: no row, no content — one generic notice. */
        INVITATION,
        /** A group the user said to ignore: nothing at all. */
        DECLINED,
        /** A 1:1 conversation this device holds. */
        DIRECT,
        /** Not known to this device yet: ask for the groups before deciding anything. */
        UNKNOWN,
    }

    /**
     * Routed by the owner of the id ([mayClaim]): an accepted group routes as the group; else a
     * held direct conversation routes as direct — neither an invitation nor an "ignored group"
     * under the same id can re-route or hide it; else invitation / ignored; else unknown.
     */
    fun route(conversationId: String, accepted: Collection<String>, invitations: Collection<String>, declined: Collection<String>, direct: Collection<String>): Route = when (conversationId) {
        in accepted -> Route.GROUP
        in direct -> Route.DIRECT
        in declined -> Route.DECLINED
        in invitations -> Route.INVITATION
        else -> Route.UNKNOWN
    }

    /**
     * May a DM event be filed under [route], given its sealed group marker (`DmEvent.isGroup`,
     * set by the core from inside the ciphertext)? A group-marked message only ever counts for a
     * group (accepted, or an invitation); a bare one never does. A marked message is never filed
     * as a direct chat — whatever the server lists and whatever entry the 1:1 store holds.
     */
    fun markerFits(route: Route, isGroup: Boolean): Boolean = when (route) {
        Route.GROUP, Route.INVITATION -> isGroup
        Route.DIRECT, Route.UNKNOWN -> !isGroup
        Route.DECLINED -> false
    }

    /**
     * Audit A16: may an UNCLAIMED direct entry give way to a group under the same id?
     * [fixedAsGroup] is what this device fixed the conversation as at first use
     * (`dm_is_group`): null = never used here. A claimed entry (the user's own action) never
     * gives way; an unclaimed one gives way unless the conversation is fixed as 1:1 here — then
     * a group under that id could never show a message, and the entry stays.
     */
    fun directGivesWay(claimed: Boolean, fixedAsGroup: Boolean?): Boolean = !claimed && fixedAsGroup != false

    /** May the user's action (start / join) make [conversationId]'s id a group? Not when this device fixed it as 1:1. */
    fun mayBecomeGroup(fixedAsGroup: Boolean?): Boolean = fixedAsGroup != false

    /** The id is held (or offered) on both sides: route by the owner, change nothing, say so once. */
    fun conflict(conversationId: String, accepted: Collection<String>, invitations: Collection<String>, direct: Collection<String>): Boolean =
        conversationId in direct && (conversationId in accepted || conversationId in invitations)

    /**
     * May this (authenticated) sender post into an accepted group? Only this account's own
     * copies and the members of the STORED set. Anyone else — a ghost the server added to the
     * conversation, say — is dropped: nothing is redrawn, nothing notifies.
     */
    fun accepts(senderId: String, fromSelf: Boolean, members: Collection<String>): Boolean = fromSelf || senderId in members

    const val OUTSIDER_TITLE = "Someone outside a group tried to post in it"
    fun outsiderMessage(groupTitle: String): String =
        "An account that is not one of the people you joined “$groupTitle” with sent something to it. Skwod did not show it."

    /** Which rows a group conversation shows: mine, and those of a member of the STORED set. */
    fun rowShown(authorId: String?, me: String?, others: Collection<String>): Boolean =
        authorId == null || authorId == "__me__" || authorId == me || authorId in others

    fun encode(groups: List<GroupConversation>): String = org.json.JSONArray().apply {
        for (g in groups) put(org.json.JSONObject().put("conversationId", g.conversationId).put("memberUserIds", org.json.JSONArray(g.others))
            .put("claimedNames", org.json.JSONObject(g.claimedNames)).put("serverDisagrees", g.serverDisagrees))
    }.toString()

    /** Tolerant, for display and tests: whatever can be read ([salvage]). Never used to decide what to WRITE. */
    fun decode(json: String?): List<GroupConversation> = if (json.isNullOrBlank()) emptyList() else salvage(json).items

    /** One stored element, or null when it is not a group (damaged, no id, a member count no group has). */
    private fun element(o: org.json.JSONObject?): GroupConversation? {
        if (o == null) return null
        val id = o.optString("conversationId")
        val m = o.optJSONArray("memberUserIds") ?: return null
        val others = (0 until m.length()).map { m.optString(it) }.filter { it.isNotEmpty() }.distinct()
        val names = o.optJSONObject("claimedNames")?.let { n -> n.keys().asSequence().associateWith { n.optString(it) } } ?: emptyMap()
        return if (id.isEmpty() || !canStart(others.size)) null else GroupConversation(id, others, names, o.optBoolean("serverDisagrees", false))
    }

    /**
     * STRICT: null unless the whole value is a list in which EVERY element is a group. A list
     * with one damaged or wrong-size element is not silently shortened (and then written back
     * without it) — the store keeps a copy of it and salvages ([salvage]).
     */
    fun decodeOrNull(json: String?): List<GroupConversation>? = try {
        if (json.isNullOrBlank()) emptyList() else {
            val arr = org.json.JSONArray(json)
            (0 until arr.length()).map { i -> element(arr.optJSONObject(i)) ?: return null }
        }
    } catch (_: Exception) { null }

    /** What can still be read of a stored list: the elements that are readable, the conversation ids of those that are not, and whether it was a list at all. */
    class Salvaged<T>(val items: List<T>, val lostIds: List<String>, val isArray: Boolean)

    fun salvage(json: String): Salvaged<GroupConversation> {
        val arr = try { org.json.JSONArray(json) } catch (_: Exception) { return Salvaged(emptyList(), emptyList(), false) }
        val items = ArrayList<GroupConversation>(); val lost = ArrayList<String>()
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i)
            val g = try { element(o) } catch (_: Exception) { null }
            if (g != null) items += g else o?.optString("conversationId")?.takeIf { it.isNotEmpty() }?.let { lost += it }
        }
        return Salvaged(items, lost, true)
    }

    /** The ignored-groups list, element by element. */
    fun salvageIds(json: String): Salvaged<String> {
        val arr = try { org.json.JSONArray(json) } catch (_: Exception) { return Salvaged(emptyList(), emptyList(), false) }
        return Salvaged((0 until arr.length()).mapNotNull { (arr.opt(it) as? String)?.takeIf { s -> s.isNotEmpty() } }, emptyList(), true)
    }

    fun encodeIds(ids: Set<String>): String = org.json.JSONArray(ids.sorted()).toString()
    fun decodeIds(json: String?): Set<String> = decodeIdsOrNull(json) ?: emptySet()
    /** null = unreadable. [ordered] keeps the stored order (a LinkedHashSet). */
    fun decodeIdsOrNull(json: String?, ordered: Boolean = false): Set<String>? = try {
        if (json.isNullOrBlank()) emptySet() else org.json.JSONArray(json).let { a ->
            (0 until a.length()).map { a.optString(it) }.filter { it.isNotEmpty() }.let { if (ordered) LinkedHashSet(it) else it.toSet() }
        }
    } catch (_: Exception) { null }

    const val MIN_OTHERS = 2
    const val MAX_OTHERS = 9
    const val SEALED_LINE = "Messages are sealed separately to every device of every member."

    fun canStart(others: Int): Boolean = others in MIN_OTHERS..MAX_OTHERS
    fun counter(others: Int): String = "$others of $MAX_OTHERS"

    /** The members of a group other than this account, in the order given, each once. */
    fun others(memberUserIds: List<String>, me: String?): List<String> = memberUserIds.filter { it.isNotEmpty() && it != me }.distinct()

    /**
     * A group's title: its members' names AS THIS DEVICE NAMES THEM (the contact book's label —
     * verified name, known name, or "‹claimed› (unverified)"), joined with ", " and cut to
     * [max] characters. There is no server-given group name, so the server cannot rename a
     * group into something it is not.
     */
    fun title(names: List<String>, max: Int = 48): String {
        val joined = names.filter { it.isNotBlank() }.joinToString(", ")
        if (joined.isEmpty()) return "Group"
        return if (joined.length <= max) joined else joined.take(max - 1).trimEnd(',', ' ') + "…"
    }

    /** "A, B and C" for a sentence. */
    fun sentenceList(names: List<String>): String = when (names.size) {
        0 -> "nobody"
        1 -> names[0]
        else -> names.dropLast(1).joinToString(", ") + " and " + names.last()
    }

    /**
     * Adding or removing someone cannot change a group — the server has no such operation, and
     * who a message is sealed to is the sender's choice. It starts a NEW group, and says so.
     */
    fun newGroupConfirm(names: List<String>): String =
        "This starts a new group with ${sentenceList(names)}. Messages already sent stay in the old one."

    /** The member set after adding [added] / removing [removed]; null when it would not be a group. */
    fun changed(others: List<String>, added: List<String> = emptyList(), removed: String? = null): List<String>? {
        val next = (others.filter { it != removed } + added).distinct()
        return if (canStart(next.size)) next else null
    }
}

/**
 * Where an upload's files live. Two kinds, never mixed: the PLAINTEXT copy of a picked item
 * (staging — exists only for the moment it takes to encrypt it) and the ciphertext the core
 * keeps while uploading (work). Both sit under the app's no-backup storage, one directory per
 * skwod, so erasing a skwod takes its uploads with it and a crash leaves nothing readable for
 * longer than the next launch.
 */
object UploadPaths {
    const val STAGING = "skwod-staging"
    const val WORK = "skwod-uploads"

    /** A workspace id as a directory name: its own characters if they are plain, else a digest. */
    fun dirName(workspaceId: String): String =
        if (workspaceId.isNotEmpty() && workspaceId.length <= 80 && workspaceId.all { it.isLetterOrDigit() && it.code < 128 || it == '-' || it == '_' }) workspaceId
        else java.security.MessageDigest.getInstance("SHA-256").digest(workspaceId.toByteArray()).take(16).joinToString("") { "%02x".format(it) }

    fun staging(root: java.io.File, workspaceId: String): java.io.File = java.io.File(java.io.File(root, STAGING), dirName(workspaceId))
    fun work(root: java.io.File, workspaceId: String): java.io.File = java.io.File(java.io.File(root, WORK), dirName(workspaceId))

    /**
     * At every launch: no upload is being prepared yet, so EVERY staged plaintext file is a
     * leftover of a crash or a kill. Deletes them all (every skwod's), plus [legacy] locations
     * older builds staged in. Returns how many files went.
     */
    fun sweepStaging(root: java.io.File, legacy: List<java.io.File> = emptyList()): Int {
        var n = 0
        for (dir in listOf(java.io.File(root, STAGING)) + legacy) {
            n += dir.walkTopDown().count { it.isFile }
            dir.deleteRecursively()
        }
        return n
    }

    /** A skwod is erased from this phone: its staged plaintext AND its ciphertext in flight go. */
    fun purge(root: java.io.File, workspaceId: String): Boolean {
        val a = staging(root, workspaceId).deleteRecursively()
        val b = work(root, workspaceId).deleteRecursively()
        return a && b
    }
}

/** Streamed uploads: which row of `pendingUploads()` belongs to an attachment, and what the bubble says. */
object UploadRules {
    /** How the core names a not-yet-uploaded attachment inside a queued message. */
    const val PLACEHOLDER_PREFIX = "upload:"

    data class Row(val uploadId: String, val sent: Long, val total: Long, val done: Boolean)

    /** The upload id behind a descriptor's blob id, or null when that is already a real blob id. */
    fun uploadId(blobId: String): String? =
        if (blobId.startsWith(PLACEHOLDER_PREFIX)) blobId.removePrefix(PLACEHOLDER_PREFIX).takeIf { it.isNotEmpty() } else null

    fun progressFor(blobId: String, rows: Collection<Row>): Row? = uploadId(blobId)?.let { id -> rows.firstOrNull { it.uploadId == id } }

    fun fraction(row: Row): Float = if (row.total <= 0) 0f else (row.sent.toFloat() / row.total.toFloat()).coerceIn(0f, 1f)

    fun line(row: Row, size: (Long) -> String): String = "Uploading… ${size(row.sent.coerceAtMost(row.total))}/${size(row.total)}"

    /** Poll about once a second while anything is still on its way. */
    fun anyPending(rows: Collection<Row>): Boolean = rows.any { !it.done }
}

/** The reports inbox of the skwod's owner. */
object ReportRules {
    fun headline(reporterName: String, subjectName: String?): String = "$reporterName reported ${subjectName ?: "a message"}"

    /** The entry shows when there is something to read, or for the instance owner. */
    fun entryVisible(count: Int, isInstanceOwner: Boolean): Boolean = count > 0 || isInstanceOwner

    /** How the quoted excerpt relates to this device's own copy of the message. */
    enum class Match(val caption: String) {
        /** No copy on this device (or the report did not say where the message is). */
        UNKNOWN("This is what the reporter says was written. Skwod can't prove who wrote it."),
        MATCHES("Matches the message on this device."),
        DIFFERS("Differs from the message on this device."),
    }

    /**
     * [cachedBodies] = the forms this device holds the message in (its raw body and its text
     * part); empty when it was not found. The excerpt is the reporter's CLAIM: only the owner's
     * own copy can back it.
     */
    fun match(excerpt: String?, found: Boolean, cachedBodies: List<String>): Match = when {
        !found || excerpt == null -> Match.UNKNOWN
        cachedBodies.any { it.trim() == excerpt.trim() } -> Match.MATCHES
        else -> Match.DIFFERS
    }

    /** The reported message as THIS device holds it (what `cachedMessage` returned). */
    data class CachedRow(val authorId: String?, val text: String, val isDeleted: Boolean = false, val isSystem: Boolean = false, val isUndecryptable: Boolean = false)

    const val SUBJECT_MISMATCH = "The reporter named a different person than the one who wrote this message."
    const val SERVER_MISMATCH = "The reporter named a different server than the one this message is in."

    /** Whom and what a report's actions would touch, as far as this device can confirm it. */
    sealed interface Resolution {
        /**
         * The message is on this device, in a channel this device knows the server of.
         * [authorId] is who actually wrote it and [serverId] the server that channel belongs to
         * here — neither is taken from the report. [warnings] say where the reporter's claim
         * disagrees; while there is one, no action is offered from the card.
         */
        data class Target(val channelId: String, val messageId: String, val authorId: String?, val authorIsMe: Boolean,
                          val serverId: String, val text: String, val warnings: List<String>) : Resolution {
            val canRemove: Boolean get() = warnings.isEmpty()
            val canModerate: Boolean get() = warnings.isEmpty() && authorId != null && !authorIsMe
        }
        /** Nothing on this device backs the report: no message to remove, nobody to act on by default. */
        data object Unresolved : Resolution
    }

    /**
     * Every field of a report except who sent it is the REPORTER's choice: the person, the
     * server, the channel, the message id. Acting on them as given would let a reporter have
     * the owner delete somebody else's message, or ban an innocent member of another server.
     * So the target is resolved from what the owner's own device holds — the cached message
     * names its real author, and this device's own space list names the channel's server —
     * and the report's claims are only COMPARED against that.
     *
     * @param cached the row `cachedMessage("channel:<channelId>", messageId)` returned, or null
     * @param channelServers channel id → server id, from this device's own space list
     */
    fun resolve(subjectUserId: String?, serverId: String?, channelId: String?, messageId: String?,
                cached: CachedRow?, channelServers: Map<String, String>, me: String?): Resolution {
        if (channelId.isNullOrEmpty() || messageId.isNullOrEmpty() || cached == null) return Resolution.Unresolved
        // A deleted row, a notice the core wrote or a placeholder is not a message anyone can be held to.
        if (cached.isDeleted || cached.isSystem || cached.isUndecryptable) return Resolution.Unresolved
        val server = channelServers[channelId]?.takeIf { it.isNotEmpty() } ?: return Resolution.Unresolved
        val mine = cached.authorId == "__me__" || (me != null && cached.authorId == me)
        val author = if (mine) me else cached.authorId?.takeIf { it.isNotEmpty() }
        val warnings = ArrayList<String>()
        if (!subjectUserId.isNullOrEmpty() && subjectUserId != author) warnings += SUBJECT_MISMATCH
        if (!serverId.isNullOrEmpty() && serverId != server) warnings += SERVER_MISMATCH
        return Resolution.Target(channelId, messageId, author, mine, server, cached.text, warnings)
    }

    /**
     * The explicit step, when nothing was resolved: the owner picks a server this account is in
     * and a person from THAT server's member list. Nothing from the report is accepted here.
     */
    fun manualChoiceValid(serverId: String?, userId: String?, myServers: Collection<String>, serverMembers: Collection<String>, me: String?): Boolean =
        !serverId.isNullOrEmpty() && !userId.isNullOrEmpty() && serverId in myServers && userId in serverMembers && userId != me

    fun confirmTitle(ban: Boolean, name: String, server: String): String = "${if (ban) "Ban" else "Kick"} $name from $server?"

    /** The report's claim, shown as a hint only. */
    fun hint(subjectName: String?, serverName: String?): String? = when {
        subjectName != null && serverName != null -> "The reporter says: $subjectName in $serverName"
        subjectName != null -> "The reporter says: $subjectName"
        serverName != null -> "The reporter says: in $serverName"
        else -> null
    }

    fun banReason(category: String): String = "reported: $category"

    fun badge(count: Int): String = if (count > 99) "99+" else "$count"
}
