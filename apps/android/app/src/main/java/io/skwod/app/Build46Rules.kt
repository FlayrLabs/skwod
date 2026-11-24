package io.skwod.app

/**
 * Build 46: the decisions behind "a refused session never logs you out", "log in needs only the
 * address, username and password", join-code typing, and one entry per skwod. Pure (no
 * android.*, no FFI) so each one is unit-tested on the JVM (`Build46Test`).
 */

/**
 * What the app does when the host refuses a request. Only ONE answer ends a session: the core's
 * `sessionState()` saying SignedOut, which it says for a 401 on `GET /api/auth/me` and nothing
 * else. Everything else keeps the token, the keys and the cache.
 */
object SessionRefusal {
    enum class Action {
        /** `sessionState()` said 401: show the login, address filled in, keys and cache kept. */
        SIGNED_OUT,
        /** The host runs a newer protocol (426 / `UpdateRequired`, or bind refused after a real rebind): banner + "Update Skwod". */
        UPDATE_APP,
        /** "device bind required": bind the session (again); not a device yet → link this device. */
        BIND_REQUIRED,
        /** Removed / superseded / a restore waiting: the existing device-state screens. */
        DEVICE_STATE,
        /** Anything else (offline, 5xx, a timeout): keep the session and try again. */
        TRANSIENT,
    }

    /** The build-45 server's words for an unbound session (HTTP 403). */
    const val BIND_REQUIRED_TEXT = "device bind required"

    /**
     * The status of a core `ClientError::Status`, written `http status <NNN>: <body>`: the FIRST
     * "http status " (the body only comes after it), exactly three digits, then ':' or the end.
     */
    fun httpStatus(detail: String?): Int? {
        val d = detail ?: return null
        val at = d.indexOf("http status ", ignoreCase = true)
        if (at < 0) return null
        val from = at + "http status ".length
        if (d.length < from + 3) return null
        val digits = d.substring(from, from + 3)
        if (!digits.all { it in '0'..'9' }) return null
        if (d.length > from + 3 && d[from + 3] != ':') return null
        return digits.toInt()
    }

    fun isBindRequired(detail: String?): Boolean = detail?.contains(BIND_REQUIRED_TEXT, ignoreCase = true) == true

    /**
     * @param kind `coreErrorKind(e)` (null for a non-core exception)
     * @param detail the error's text
     * @param sessionSignedOut `sessionState()` answered SignedOut (a real 401 on /api/auth/me)
     * @param boundDevice this install is a registered device whose session `bindSession()` bound
     * @param reboundAlready the session was bound again on a FRESH client after a refusal, and the host still refuses
     */
    fun decide(
        kind: String?,
        detail: String?,
        sessionSignedOut: Boolean = false,
        boundDevice: Boolean = false,
        reboundAlready: Boolean = false,
    ): Action {
        if (sessionSignedOut) return Action.SIGNED_OUT
        if (kind == "UpdateRequired") return Action.UPDATE_APP
        if (InstallRoute.isDeviceError(kind)) return Action.DEVICE_STATE
        val d = detail.orEmpty().lowercase()
        if (d.contains("device removed") || d.contains("device superseded")) return Action.DEVICE_STATE
        if (isBindRequired(d)) {
            // A freshly logged-in install that is not a device yet is unbound BY DESIGN: that is
            // the link-this-device flow, never "update Skwod". Only a device whose session was
            // really bound, on a fresh client, and is still refused means the two disagree.
            return if (boundDevice && reboundAlready) Action.UPDATE_APP else Action.BIND_REQUIRED
        }
        // Only the typed error (above) or the HTTP status the core reports — never a "426" or
        // "upgrade required" anywhere in the server's words. (The core already turns every 426
        // into UpdateRequired.)
        if (httpStatus(d) == 426) return Action.UPDATE_APP
        // A 401 anywhere else is NOT a sign-out: the caller asks sessionState() before deciding.
        return Action.TRANSIENT
    }
}

/**
 * The address field of the connect screen. "Log in" takes an address only — the code in a pasted
 * invite is ignored — and the address may be any of: an `https://skwod.io/join#…` share link
 * (with or without its code), a `skwod://join/…` link, the bare 52-character host key (optionally
 * followed by `.CODE`), a classic `https://host[#code]` address, or a bare host name.
 */
object LoginAddress {
    private const val ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"

    /** Exactly a host key: 52 z-base-32 characters (any case). */
    fun isBareNodeId(s: String): Boolean = s.length == 52 && s.lowercase().all { it in ZBASE32 }

    /** Address and code as typed/pasted. Throws [InviteException] for anything that names no skwod. */
    fun parse(raw: String): ParsedInvite {
        val t = raw.trim()
        val dot = t.indexOf('.')
        val head = if (dot >= 0) t.substring(0, dot) else t
        if (isBareNodeId(head) && !t.contains("://") && !t.contains('#') && !t.contains('/')) {
            val code = if (dot >= 0) t.substring(dot + 1) else ""
            return InviteLink.parse(InviteLink.P2P_PREFIX + head.lowercase() + if (code.isNotEmpty()) "#$code" else "")
        }
        return InviteLink.parse(t)
    }

    /**
     * Where to log in. A code is not needed and never blocks: a classic link whose `#code` part is
     * not a valid code still names its address.
     */
    fun forLogin(raw: String): SkwodAddress = try { parse(raw).address } catch (e: InviteException) {
        val t = raw.trim()
        if (e.reason == InviteException.Reason.BadCode && t.contains('#') && !InviteLink.isOnShareOrigin(t) && !t.startsWith("skwod:", true))
            InviteLink.parse(t.substringBefore('#')).address
        else throw e
    }
}

/** What the connect screen asks for in each mode. */
object AuthForm {
    /** Only "Create account" needs an invite's code. "Log in" is address + username + password. */
    fun codeNeeded(createAccount: Boolean): Boolean = createAccount

    /**
     * The join code to sign up with: the invite's own, else the one typed into the code field
     * (normalised). null = none (or not a valid code).
     */
    fun signupCode(linkCode: String?, typed: String): String? =
        linkCode ?: JoinCode.normalise(typed).takeIf { it.isNotEmpty() && InviteLink.isValidCode(it) }

    /** May the button be pressed? */
    fun canSubmit(createAccount: Boolean, address: String, username: String, password: String, code: String?): Boolean {
        if (address.isBlank() || username.isBlank() || password.isBlank()) return false
        if (!createAccount) return true
        return password.length >= 8 && code != null
    }

    /**
     * Which mode a link handed to the form (deep link, scan, paste) puts it in. A link with a
     * code opens Create account — unless the user is already on Log in, where the code is ignored.
     * A bare address always means Log in, except on Create account where the code is typed next.
     */
    fun modeAfterAdopting(createAccount: Boolean, hasCode: Boolean, fromUserAction: Boolean): Boolean = when {
        !fromUserAction -> hasCode            // a tapped link / "log in again": what the link says
        else -> createAccount                 // the user picked the mode: keep it
    }
}

/**
 * A join code as people type it. Codes are minted by the server in upper case from
 * `A–Z 2–9` (`ABCD2345`, `SKWD-ABCD-EFGH`), and compared exactly. Typing must never be blocked, so
 * this only runs on submit: spaces go, case goes up, `SKWD` codes get their dashes back, and a
 * plain 8-character code typed with a dash (`ABCD-2345`) loses it.
 */
object JoinCode {
    fun normalise(raw: String): String {
        val kept = raw.filter { !it.isWhitespace() }.uppercase()
            .replace(Regex("-{2,}"), "-").trim('-')
        val bare = kept.replace("-", "")
        if (bare.startsWith("SKWD") && bare.length == 12 && bare.all { it.isLetterOrDigit() })
            return "SKWD-${bare.substring(4, 8)}-${bare.substring(8, 12)}"
        if (bare.length == 8 && bare.all { it.isLetterOrDigit() }) return bare
        return kept
    }

    /** "Join with a code": the code from a whole invite link, or a typed code (normalised). */
    fun extract(raw: String): String {
        val t = raw.trim()
        if (t.contains("://") || t.contains('#') || LoginAddress.isBareNodeId(t.substringBefore('.'))) {
            val code = try { LoginAddress.parse(t).joinCode } catch (_: InviteException) { null }
            if (code != null) return code
        }
        return normalise(t)
    }
}

/**
 * One entry per skwod and account. Two records are the same skwod when they share the account and
 * either the p2p host key, the same https address, or the same instance id AND the same pinned
 * server key (both were proven to the device when pinned — not a claim). The entry kept is the
 * one with a live session, the newest; the others' RECORDS go (their cache files are left on disk).
 */
object WorkspaceDedupe {
    data class Result(val kept: List<Workspace>, val dropped: List<Workspace>, val replacedBy: Map<String, String>)

    /**
     * [crossAddress]: also match the same instance id + pinned key across different addresses —
     * only for records already on the device, never right after a login, where those values are
     * what the host just said (a host must not be able to reach another skwod's entry).
     */
    fun sameSkwod(a: Workspace, b: Workspace, crossAddress: Boolean = false): Boolean {
        if (a.userId != b.userId) return false
        if (a.nodeId != null && a.nodeId == b.nodeId) return true
        if (!a.isP2P && !b.isP2P && normalisedServer(a.server) == normalisedServer(b.server)) return true
        if (!crossAddress) return false
        return a.instanceId != null && a.instanceId == b.instanceId && a.pinnedKey != null && a.pinnedKey == b.pinnedKey
    }

    private fun normalisedServer(s: String): String = s.trim().trimEnd('/').lowercase()

    /** Better first: a live session, then the newest token, then the earlier record. */
    private fun better(a: Workspace, b: Workspace): Workspace {
        if (a.isSignedOut != b.isSignedOut) return if (!a.isSignedOut) a else b
        if (a.signedOutByUser != b.signedOutByUser) return if (!a.signedOutByUser) a else b
        return if (b.tokenIssuedAt > a.tokenIssuedAt) b else a
    }

    /** Only a duplicate WITHOUT a session is ever dropped: a record that still has a token stays. */
    fun merge(list: List<Workspace>, crossAddress: Boolean = false): Result {
        val groups = ArrayList<MutableList<Workspace>>()
        for (w in list) {
            val g = groups.firstOrNull { grp -> grp.any { sameSkwod(it, w, crossAddress) } }
            if (g != null) g.add(w) else groups.add(mutableListOf(w))
        }
        val kept = ArrayList<Workspace>(); val dropped = ArrayList<Workspace>(); val replaced = HashMap<String, String>()
        for (g in groups) {
            val keep = g.reduce(::better)
            kept.add(keep)
            for (w in g) if (w !== keep) {
                if (w.isSignedOut) { dropped.add(w); replaced[w.localId] = keep.localId } else kept.add(w)
            }
        }
        // Keep the original order of what stays.
        return Result(list.filter { w -> kept.any { it === w } }, dropped, replaced)
    }
}

/** How the skwod list and rail name an entry, so two entries for the same host can be told apart. */
object WorkspaceLabel {
    /** The name, always with the short host key beside it for a p2p skwod; twins also get the account. */
    fun of(w: Workspace, all: List<Workspace>): String {
        val name = w.displayName
        val twins = all.count { it.displayName == name } > 1
        // Beside a name the HOST chose, always the real address: the short host key for p2p,
        // the host name for https (never the host's words alone).
        val hostNamed = !w.nameSetByUser && w.instanceName != null
        val where = w.nodeId?.let { InviteLink.shortKey(it) }
            ?: if (hostNamed) (try { java.net.URI(w.server).host } catch (_: Exception) { null } ?: w.server) else null
        val who = if (twins) w.username?.let { "@$it" } else null
        return listOfNotNull(name, where, who).joinToString(" · ")
    }

    /** Another record is this same skwod and account. */
    fun hasTwin(w: Workspace, all: List<Workspace>): Boolean = all.any { it !== w && it.localId != w.localId && WorkspaceDedupe.sameSkwod(it, w) }

    fun state(w: Workspace): String? = if (w.isSignedOut) "Signed out — tap to log in again" else null
}

/** A tap on a skwod tile / row. */
object SkwodTap {
    enum class Outcome {
        /** The skwod on screen and working: nothing is torn down (only the view changes). */
        STAY,
        /** Its session is over: open the login for it, leave the active skwod as it is. */
        LOG_IN,
        /** Switch to it. */
        SWITCH,
    }

    fun outcome(tapped: Workspace, current: Workspace?, engineUp: Boolean): Outcome = when {
        tapped.isSignedOut && tapped.localId != current?.localId -> Outcome.LOG_IN
        tapped.localId == current?.localId && engineUp && !tapped.isSignedOut -> Outcome.STAY
        tapped.localId == current?.localId && tapped.isSignedOut -> Outcome.LOG_IN
        else -> Outcome.SWITCH
    }
}

/** Logging in would have made a second entry for a skwod already on this phone; nothing was changed. */
class SkwodIdentityException(message: String) : Exception(message)

/** What may be pasted into the composer as a picture. */
/**
 * Whose composer a paste belongs to (Apple's `StagingRule`). Each paste is tagged with the
 * conversation it started in; a result that arrives after a switch (or from a surface with no
 * conversation id) is dropped, never staged in another conversation.
 */
object StagingRule {
    fun belongs(startedFor: String, current: String): Boolean = startedFor.isNotEmpty() && startedFor == current
}

object ClipboardImage {
    /** The clip offers a picture (by its MIME types). */
    fun isImage(mimeTypes: List<String>): Boolean = mimeTypes.any { it.lowercase().startsWith("image/") }

    /**
     * A clip's URI is untrusted (any app can put one on the clipboard): only `content://`, and
     * never one served by THIS app — that would send this app's own private files.
     */
    fun mayRead(scheme: String?, authority: String?, ownAuthorities: Set<String>): Boolean =
        scheme.equals("content", ignoreCase = true) && !authority.isNullOrEmpty() && authority !in ownAuthorities
}

/**
 * The long-press menu of a SERVER (rail tile, overview row, header). Only what the user may do:
 * the owner deletes (nobody can leave their own server — the host refuses it); everyone else
 * leaves. "Mark as read" and "Copy server link" are not offered: the app keeps no unread state,
 * and a server has no link other than an invite.
 */
object ServerMenu {
    enum class Item { MUTE, INVITE, RENAME, ICON, PERMISSIONS, LEAVE, DELETE }

    /** Who owns a server, as far as THIS device can tell. */
    enum class Ownership {
        /** The core's pinned owner is this account. */
        OWNER,
        /** The pinned owner is someone else. */
        MEMBER,
        /** Nothing is pinned: the host's word alone, which never decides. */
        UNVERIFIED,
    }

    /**
     * The core's PINNED owner (`spaceOwner`) is the trust boundary. The host's `owner_id`
     * (GET /api/servers) never decides: it is ignored when a pin exists (disagreement → the pin),
     * and with no pin the answer is [Ownership.UNVERIFIED].
     */
    fun ownership(pinnedOwner: String?, me: String?): Ownership = when {
        me.isNullOrEmpty() || pinnedOwner.isNullOrEmpty() -> Ownership.UNVERIFIED
        pinnedOwner == me -> Ownership.OWNER
        else -> Ownership.MEMBER
    }

    /**
     * Leave forgets the server's keys, so it is NEVER offered to the pinned owner. Unverified:
     * the one the host's hint points at (Delete if it names me, else Leave), always behind a
     * warning ([warns]); the host enforces both anyway.
     */
    fun items(ownership: Ownership, hostSaysOwner: Boolean = false): List<Item> = buildList {
        add(Item.MUTE); add(Item.INVITE)
        val owner = ownership == Ownership.OWNER
        if (owner) { add(Item.RENAME); add(Item.ICON); add(Item.PERMISSIONS) }
        add(when (ownership) {
            Ownership.OWNER -> Item.DELETE
            Ownership.MEMBER -> Item.LEAVE
            Ownership.UNVERIFIED -> if (hostSaysOwner) Item.DELETE else Item.LEAVE
        })
    }

    /** The confirmation must say that ownership could not be checked. */
    fun warns(ownership: Ownership): Boolean = ownership == Ownership.UNVERIFIED

    /** "Mute server" mutes each of its channels (the mute store has channel, DM and skwod keys). */
    fun muteKeys(channelIds: List<String>): List<String> = channelIds.filter { it.isNotEmpty() }.map { "channel:$it" }
}

/**
 * The long-press menu of a SKWOD entry. Everything but switching acts on the skwod that is open,
 * so a skwod that is not open offers only to open it (or to log in, when its session is over).
 * The instance owner can rename the skwod on its host ("Rename on host", device-signed through
 * the core's `setInstanceName`); every member then sees that name beside the host key.
 */
object SkwodMenu {
    enum class Item { OPEN, LOG_IN, RENAME, MUTE, DEVICES, SIGN_OUT, REMOVE_FROM_DEVICE, REMOVE_DUPLICATE }

    /** The core has `setInstanceName` (build 46). */
    const val RENAME_AVAILABLE = true

    /**
     * [duplicate]: another entry is the same skwod and account (same host key or the same https
     * address — [WorkspaceDedupe.sameSkwod]); this record can then be removed on its own (its
     * files stay). Never offered for the skwod that is open.
     */
    fun items(isOpen: Boolean, signedOut: Boolean, duplicate: Boolean = false, instanceOwner: Boolean = false,
              renameAvailable: Boolean = RENAME_AVAILABLE): List<Item> {
        val base = when {
            signedOut -> listOf(Item.LOG_IN)
            !isOpen -> listOf(Item.OPEN)
            else -> listOfNotNull(Item.RENAME.takeIf { instanceOwner && renameAvailable },
                Item.MUTE, Item.DEVICES, Item.SIGN_OUT, Item.REMOVE_FROM_DEVICE)
        }
        return if (duplicate && !isOpen) base + Item.REMOVE_DUPLICATE else base
    }

    /** The heading over the server list: which skwod (host) these servers are in. */
    fun heading(name: String): String = if (name.contains("skwod", ignoreCase = true)) name else "Skwod: $name"
}

/**
 * Logging in to a skwod this phone already has, through its OTHER address (p2p ↔ https). The
 * entry is reused only on PROOF — the transport-authenticated host key, or the existing entry's
 * pinned key challenged over the new address — and a p2p entry keeps its p2p address. What the
 * host merely claims (instance id) only picks the entry to challenge. Unproven: refused, never
 * a second entry.
 */
object LoginReuse {
    sealed class Decision {
        data class Reuse(val existing: Workspace, val keepsP2p: Boolean) : Decision()
        data object New : Decision()
        data object Refuse : Decision()
    }

    const val REFUSED = "Skwod couldn't confirm this is the same Skwod you already have on this phone, so nothing was changed. Check your connection and try again."

    suspend fun decide(
        workspaces: List<Workspace>, address: SkwodAddress, userId: String, claimedInstanceId: String?,
        prove: suspend (pinnedKey: String) -> Boolean,
    ): Decision {
        WorkspaceMatch.find(workspaces, address, userId, claimedInstanceId, prove)?.let { return Decision.Reuse(it, keepsP2p = false) }
        // Same address and account, key not proven just now: no second entry.
        if (workspaces.any { it.userId == userId && it.server == address.stored && it.pinnedKey != null }) return Decision.Refuse
        val claimed = claimedInstanceId ?: return Decision.New
        val candidates = workspaces.filter { w ->
            w.userId == userId && w.instanceId == claimed && w.pinnedKey != null &&
                // Never onto a DIFFERENT p2p host: a host key is the identity.
                !(address is SkwodAddress.P2p && w.nodeId != null && w.nodeId != address.nodeId)
        }
        if (candidates.isEmpty()) return Decision.New
        for (c in candidates) {
            val proven = try { prove(c.pinnedKey!!) } catch (_: Exception) { false }
            if (proven) return Decision.Reuse(c, keepsP2p = address is SkwodAddress.Https && c.isP2P)
        }
        return Decision.Refuse
    }
}

/** `GET /api/servers` (the servers this account is a member of, with their owners). */
object ServerList {
    /** server_id → owner_id; null unless the answer parsed completely. */
    fun owners(json: String?): Map<String, String>? {
        if (json == null) return null
        return try {
            val arr = org.json.JSONObject(json).getJSONArray("servers")
            val out = LinkedHashMap<String, String>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val id = o.getString("server_id"); if (id.isEmpty()) return null
                out[id] = o.optString("owner_id")
            }
            out
        } catch (_: Exception) { null }
    }

    /** Listed here but not in the answer: deleted, or this account was removed. */
    fun gone(local: Collection<String>, listed: Set<String>): Set<String> =
        local.filter { it.isNotEmpty() && it != "demo" && it !in listed }.toSet()

    /** What the HOST says (a hint for [ServerMenu.items] when nothing is pinned — never a decision). */
    fun hostSaysOwner(owners: Map<String, String>, serverId: String, me: String?): Boolean =
        !me.isNullOrEmpty() && owners[serverId] == me
}

/**
 * A skwod's name. Priority: the user's own name for it on this device, then the name its host
 * set (`GET /api/instance/name`), then what the address suggests. A host's name is cleaned
 * (nothing invisible or steering, one line, at most [MAX] characters) and refused when it reads
 * like another entry's name or like a generic one.
 */
object SkwodName {
    const val MAX = 32

    /**
     * One line, at most [MAX] characters, without control or bidi-steering characters (and no
     * other invisible formatting, except the ZWJ that joins emoji: [hostCharactersAllowed]
     * decides where that may stand). Used for every name; the host's is then checked further.
     */
    fun clean(raw: String?): String? {
        if (raw == null) return null
        val sb = StringBuilder()
        var i = 0
        val t = raw.replace(Regex("\\s+"), " ")
        while (i < t.length) {
            val cp = t.codePointAt(i); i += Character.charCount(cp)
            val type = Character.getType(cp)
            if (type == Character.CONTROL.toInt()) continue
            if (type == Character.FORMAT.toInt() && cp != 0x200D) continue     // bidi controls, ZWSP, tags, …
            sb.appendCodePoint(cp)
        }
        val cps = sb.toString().trim().codePoints().toArray()
        val capped = String(cps, 0, minOf(cps.size, MAX)).trim()
        return capped.ifEmpty { null }
    }

    /** A host-supplied name that reads like an address: as written, after NFKC, or as its look-alike skeleton. */
    fun looksLikeAddress(name: String): Boolean =
        listOf(name, NameSkeleton.fold(name), NameSkeleton.skeleton(name)).any { n -> n.any { it == '.' || it == ':' || it == '/' || it == '\\' || it == '@' } }

    /** Names a host may not give a skwod (compared as look-alike skeletons). Same list as Apple's `SkwodNameRule.reserved`. */
    val RESERVED = listOf("skwod", "my skwod", "this mac", "home", "direct messages", "feed")

    /**
     * THE rule for a name a HOST supplies — identical to Apple's `SkwodNameRule.acceptLearned`,
     * with the vectors in `apps/shared-test-vectors/skwod-names.json`: runs of spaces become
     * one space and the ends are trimmed (tabs and newlines are refused); every character must be allowed
     * ([HostNameChars.units]); at most [MAX] units (an ASCII character or one whole emoji
     * sequence); never address-like or reserved. Null = refused (the entry keeps its default
     * name beside its host key). A name the user sets on this device is not held to this.
     */
    fun hostName(raw: String?): String? {
        if (raw == null) return null
        val spaced = raw.replace(Regex(" +"), " ").trim(' ')
        if (spaced.isEmpty() || spaced.codePointCount(0, spaced.length) > HostNameChars.MAX_SCALARS) return null
        val units = HostNameChars.units(spaced) ?: return null
        val capped = units.take(MAX).joinToString("").trim(' ')
        if (capped.isEmpty() || looksLikeAddress(capped)) return null
        val sk = NameSkeleton.skeleton(capped)
        if (RESERVED.any { NameSkeleton.skeleton(it) == sk }) return null
        return capped
    }

    /** Does every character of [name] pass the host rule? */
    fun hostCharactersAllowed(name: String): Boolean = HostNameChars.units(name) != null

    /** May [name] be shown for one entry, given the names the OTHER entries show? */
    fun accepted(name: String, others: List<String>): Boolean {
        if (hostName(name) != name) return false
        val sk = NameSkeleton.skeleton(name)
        return others.none { NameSkeleton.skeleton(it) == sk }
    }

    /**
     * Re-check every host-supplied name against the whole list (on load, on save, on every
     * added entry — not once). A host name that reads like ANY other entry's name, its own
     * address-based / user-set name or its host name, is dropped: those win on a clash.
     */
    fun revalidate(list: List<Workspace>): List<Workspace> = list.map { w ->
        val n = w.instanceName ?: return@map w
        val others = list.filter { it.localId != w.localId }.flatMap { o ->
            listOfNotNull(if (o.nameSetByUser) o.name else null, Workspace.defaultName(o.server), o.instanceName)
        }
        if (accepted(n, others)) w else w.copy(instanceName = null)
    }

    fun display(userName: String?, instanceName: String?, fallback: String): String =
        userName?.takeIf { it.isNotBlank() } ?: instanceName?.takeIf { it.isNotBlank() } ?: fallback

    /** `{"name": "…"|null}`; null for no name or anything unreadable. */
    fun parse(json: String?): String? {
        if (json == null) return null
        return try {
            val o = org.json.JSONObject(json)
            if (o.isNull("name")) null else hostName(o.optString("name"))
        } catch (_: Exception) { null }
    }
}

/**
 * Who is typing in the open chat — the Apple apps' `TypingState`. The host relays a `typing`
 * event (`{"user_id"}`) on the chat's topic; each typer is shown until [EXPIRE_MS] after their
 * last event, or until their message arrives. Never myself, never someone blocked, and nothing at
 * all while the "Send typing indicators" setting is off (it gates sending AND showing). Immutable.
 */
data class TypingState(val until: Map<String, Long> = emptyMap()) {
    companion object {
        const val SETTING_KEY = "privacy.typingIndicators"
        /** A typer disappears this long after their last event. */
        const val EXPIRE_MS = 5_000L
        /** I announce at most once per this long while typing. */
        const val SEND_EVERY_MS = 3_000L

        /** May an "I'm typing" go out now? Never for an empty composer, never with the setting off. */
        fun mayAnnounce(enabled: Boolean, draft: String, lastSentAt: Long, now: Long): Boolean =
            enabled && draft.isNotBlank() && (lastSentAt <= 0 || now < lastSentAt || now - lastSentAt >= SEND_EVERY_MS)

        /** "Sam is typing…", "Sam and Kim are typing…", "Several people are typing…"; null for nobody. */
        fun text(names: List<String>): String? = when (names.size) {
            0 -> null
            1 -> "${names[0]} is typing…"
            2 -> "${names[0]} and ${names[1]} are typing…"
            else -> "Several people are typing…"
        }
    }

    fun add(userId: String, me: String?, blocked: Boolean, enabled: Boolean, now: Long): TypingState {
        if (!enabled || userId.isEmpty() || userId == me || blocked) return this
        return TypingState(until + (userId to now + EXPIRE_MS))
    }

    /** Their message arrived (or they left): no longer typing. */
    fun remove(userId: String): TypingState = if (userId in until) TypingState(until - userId) else this

    fun expire(now: Long): TypingState = until.filterValues { it > now }.let { if (it.size == until.size) this else TypingState(it) }

    /** Who is typing now, in the order they started. */
    fun typers(now: Long): List<String> = until.filterValues { it > now }.keys.toList()
}

/**
 * The characters a host-supplied skwod name may use — one explicit table, the same as Apple's
 * `HostNameChars` (never the platform's Unicode properties, which differ by OS version).
 */
object HostNameChars {
    private const val ZWJ = 0x200D
    private const val VS16 = 0xFE0F
    /** Most pictographs one ZWJ sequence may join (a family of four). Same as Apple. */
    const val MAX_JOINED = 4
    /** Most code points a host-supplied name may have before it is capped. Same as Apple. */
    const val MAX_SCALARS = 128

    /** Unicode Extended_Pictographic (emoji-data 15.1), without skin tones or regional indicators. */
    private val PICTOGRAPHIC: List<IntRange> = listOf(
        0x00A9..0x00A9, 0x00AE..0x00AE, 0x203C..0x203C, 0x2049..0x2049, 0x2122..0x2122, 0x2139..0x2139,
        0x2194..0x2199, 0x21A9..0x21AA, 0x231A..0x231B, 0x2328..0x2328, 0x2388..0x2388, 0x23CF..0x23CF,
        0x23E9..0x23F3, 0x23F8..0x23FA, 0x24C2..0x24C2, 0x25AA..0x25AB, 0x25B6..0x25B6, 0x25C0..0x25C0,
        0x25FB..0x25FE, 0x2600..0x2605, 0x2607..0x2612, 0x2614..0x2685, 0x2690..0x2705, 0x2708..0x2712,
        0x2714..0x2714, 0x2716..0x2716, 0x271D..0x271D, 0x2721..0x2721, 0x2728..0x2728, 0x2733..0x2734,
        0x2744..0x2744, 0x2747..0x2747, 0x274C..0x274C, 0x274E..0x274E, 0x2753..0x2755, 0x2757..0x2757,
        0x2763..0x2767, 0x2795..0x2797, 0x27A1..0x27A1, 0x27B0..0x27B0, 0x27BF..0x27BF, 0x2934..0x2935,
        0x2B05..0x2B07, 0x2B1B..0x2B1C, 0x2B50..0x2B50, 0x2B55..0x2B55, 0x3030..0x3030, 0x303D..0x303D,
        0x3297..0x3297, 0x3299..0x3299,
        0x1F000..0x1F0FF, 0x1F10D..0x1F10F, 0x1F12F..0x1F12F, 0x1F16C..0x1F171, 0x1F17E..0x1F17F,
        0x1F18E..0x1F18E, 0x1F191..0x1F19A, 0x1F1AD..0x1F1E5, 0x1F201..0x1F20F, 0x1F21A..0x1F21A,
        0x1F22F..0x1F22F, 0x1F232..0x1F23A, 0x1F23C..0x1F23F, 0x1F249..0x1F3FA, 0x1F400..0x1F53D,
        0x1F546..0x1F64F, 0x1F680..0x1F6FF, 0x1F774..0x1F77F, 0x1F7D5..0x1F7FF, 0x1F80C..0x1F80F,
        0x1F848..0x1F84F, 0x1F85A..0x1F85F, 0x1F888..0x1F88F, 0x1F8AE..0x1F8FF, 0x1F90C..0x1F93A,
        0x1F93C..0x1F945, 0x1F947..0x1FAFF, 0x1FC00..0x1FFFD,
    )

    /**
     * Extended_Pictographic code points that read as letters, punctuation, arrows or plain
     * shapes rather than pictures: (c) (R) TM !! !? (i), arrows, the circled M, small squares
     * and triangles, the wavy dash, part-alternation mark and the circled ideographs. Refused.
     */
    private val SYMBOL_LIKE: List<IntRange> = listOf(
        0x00A9..0x00A9, 0x00AE..0x00AE, 0x203C..0x203C, 0x2049..0x2049, 0x2122..0x2122, 0x2139..0x2139,
        0x2194..0x2199, 0x21A9..0x21AA, 0x24C2..0x24C2, 0x25AA..0x25AB, 0x25B6..0x25B6, 0x25C0..0x25C0,
        0x25FB..0x25FE, 0x27A1..0x27A1, 0x2934..0x2935, 0x2B05..0x2B07, 0x3030..0x3030, 0x303D..0x303D,
        0x3297..0x3297, 0x3299..0x3299,
    )

    fun isPictograph(cp: Int): Boolean = PICTOGRAPHIC.any { cp in it } && SYMBOL_LIKE.none { cp in it }
    fun isSkinTone(cp: Int): Boolean = cp in 0x1F3FB..0x1F3FF
    fun isRegionalIndicator(cp: Int): Boolean = cp in 0x1F1E6..0x1F1FF
    private fun isAsciiAllowed(cp: Int): Boolean =
        cp in 'a'.code..'z'.code || cp in 'A'.code..'Z'.code || cp in '0'.code..'9'.code ||
            cp == ' '.code || cp == '-'.code || cp == '_'.code || cp == '\''.code || cp == '&'.code

    /**
     * [s] split into units — one ASCII character, one flag (a regional-indicator PAIR) or one
     * emoji sequence: a pictograph with an optional skin tone or VS16, joined by ZWJ only to
     * another such pictograph — or null when anything else appears (a lone skin tone, VS16 or
     * ZWJ, an odd regional indicator, a keycap, tag characters, another script, a mark, ...).
     */
    fun units(s: String): List<String>? {
        val cps = s.codePoints().toArray()
        val out = ArrayList<String>()
        var i = 0
        fun piece(from: Int, to: Int) = String(cps, from, to - from)
        while (i < cps.size) {
            val c = cps[i]
            when {
                isAsciiAllowed(c) -> { out.add(piece(i, i + 1)); i += 1 }
                isRegionalIndicator(c) -> {
                    if (i + 1 >= cps.size || !isRegionalIndicator(cps[i + 1])) return null
                    out.add(piece(i, i + 2)); i += 2
                }
                isPictograph(c) -> {
                    var j = i + 1
                    var pictographs = 1
                    if (j < cps.size && (isSkinTone(cps[j]) || cps[j] == VS16)) j++
                    while (j + 1 < cps.size && cps[j] == ZWJ && isPictograph(cps[j + 1])) {
                        // At most [MAX_JOINED] pictographs in one sequence: a longer chain is refused.
                        if (++pictographs > MAX_JOINED) return null
                        j += 2
                        if (j < cps.size && (isSkinTone(cps[j]) || cps[j] == VS16)) j++
                    }
                    out.add(piece(i, j)); i = j
                }
                else -> return null
            }
        }
        return out
    }
}
