package io.skwod.app

/**
 * @mentions, inside the ENCRYPTED message text — the server never learns who was mentioned. The
 * same wire format as the Apple apps:
 *
 *     <visible text> U+2063 <payload as Unicode TAG characters>
 *
 * The payload is `"M1" + {"m":[["<user_id>",<start>,<length>],…],"e":true}` (`"e"` only for
 * @everyone), every ASCII character c (0x20–0x7E) written as U+E0000+c, which no renderer shows:
 * an older app simply shows the visible text with its plain "@name". Offsets are UTF-16 code
 * units (Kotlin String indices) into the VISIBLE text; each range is a mention token inside it
 * ([isMentionRange]: '@' and a name of letters, digits, marks and `_ . -`, at most [MAX_RANGE]
 * units, after whitespace or punctuation; ranges never overlap or touch). Parsing takes the LAST U+2063 whose remainder is entirely tag characters; anything wrong
 * with the payload means "no mentions" (the trailer is still stripped). Caps: a trailer of at most
 * [MAX_TRAILER] tag characters, at most [MAX_MENTIONS] mentions. Pure Kotlin + org.json.
 */
object Mentions {
    const val SEPARATOR = '⁣'
    const val PREFIX = "M1"
    const val MAX_TRAILER = 4096
    const val MAX_MENTIONS = 50
    private const val TAG_BASE = 0xE0000

    data class Mention(val userId: String, val start: Int, val length: Int)

    data class Decoded(val text: String, val mentions: List<Mention> = emptyList(), val everyone: Boolean = false)

    private fun isTag(cp: Int) = cp in (TAG_BASE + 0x20)..(TAG_BASE + 0x7E)

    /** [text] with its mentions appended as the invisible trailer (nothing appended when there are none). */
    fun encode(text: String, mentions: List<Mention>, everyone: Boolean = false): String {
        val kept = valid(text, mentions)
        if (kept.isEmpty() && !everyone) return text
        val m = org.json.JSONArray()
        for (x in kept) m.put(org.json.JSONArray().put(x.userId).put(x.start).put(x.length))
        val o = org.json.JSONObject().put("m", m)
        if (everyone) o.put("e", true)
        val payload = PREFIX + o.toString()
        if (payload.any { it.code !in 0x20..0x7E } || payload.length > MAX_TRAILER) return text
        val sb = StringBuilder(text).append(SEPARATOR)
        for (ch in payload) sb.appendCodePoint(TAG_BASE + ch.code)
        return sb.toString()
    }

    /** The visible text, the mentions that are valid for it, and @everyone. Never throws. */
    fun decode(body: String): Decoded {
        val sep = body.lastIndexOf(SEPARATOR)
        if (sep < 0) return Decoded(body)
        val rest = body.substring(sep + 1)
        // Only a remainder made entirely of tag characters is a trailer.
        val cps = rest.codePoints().toArray()
        if (cps.isEmpty() || !cps.all(::isTag)) return Decoded(body)
        val text = body.substring(0, sep)
        if (cps.size > MAX_TRAILER) return Decoded(text)
        val payload = String(CharArray(cps.size) { (cps[it] - TAG_BASE).toChar() })
        if (!payload.startsWith(PREFIX)) return Decoded(text)
        return try {
            val o = org.json.JSONObject(payload.substring(PREFIX.length))
            val arr = when (val m = o.opt("m")) {
                null -> org.json.JSONArray()
                is org.json.JSONArray -> m
                else -> return Decoded(text)
            }
            if (arr.length() > MAX_MENTIONS) return Decoded(text)
            // Every value here is the SENDER's: strict types (no coercion of strings, fractions
            // or huge numbers, which optInt would silently truncate) and no addition before the
            // bounds are known.
            val raw = (0 until arr.length()).mapNotNull { i ->
                val e = arr.opt(i) as? org.json.JSONArray ?: return@mapNotNull null
                if (e.length() != 3) return@mapNotNull null
                val uid = e.opt(0) as? String ?: return@mapNotNull null
                val start = exactInt(e.opt(1)) ?: return@mapNotNull null
                val len = exactInt(e.opt(2)) ?: return@mapNotNull null
                if (uid.isEmpty() || uid.toByteArray().size > 128) null else Mention(uid, start, len)
            }
            Decoded(text, valid(text, raw), o.opt("e") == true)
        } catch (_: Exception) { Decoded(text) }
    }

    /** `start until start+length` lies inside [count] — checked without any addition (no Int wrap). */
    fun inBounds(start: Int, length: Int, count: Int): Boolean =
        start >= 0 && length >= 1 && count >= 0 && start <= count && length <= count - start

    /**
     * A JSON number that is exactly a non-negative integer no larger than Int.MAX_VALUE; strings,
     * booleans, fractions, NaN, infinities and anything larger are null.
     */
    fun exactInt(v: Any?): Int? = when (v) {
        is Int -> v.takeIf { it >= 0 }
        is Long -> v.takeIf { it in 0..Int.MAX_VALUE.toLong() }?.toInt()
        is Double -> v.takeIf { it.isFinite() && it == Math.floor(it) && it >= 0 && it <= Int.MAX_VALUE }?.toInt()
        is Float -> exactInt(v.toDouble())
        is java.math.BigInteger -> v.takeIf { it.signum() >= 0 && it.bitLength() < 32 }?.toInt()
        is java.math.BigDecimal -> runCatching { v.intValueExact() }.getOrNull()?.takeIf { it >= 0 }
        else -> null
    }

    /** What may be shown / copied / edited / put in a notification: the text without its trailer. */
    fun visible(body: String): String = decode(body).text

    /** The longest mention token, in UTF-16 units ('@' included). */
    const val MAX_RANGE = 64
    /** The most text all of a message's mentions may cover together. */
    const val MAX_COVERED = MAX_MENTIONS * MAX_RANGE

    /**
     * A range a mention may replace on screen: inside [text], 2..[MAX_RANGE] units, an '@' at the
     * start of the text or after whitespace or punctuation, then only letters, digits, combining
     * marks attached to a letter, and `_ . -` (an ALLOW-list: blanks, fillers, invisible, bidi,
     * variation and tag characters are all refused). Anything else would let a mention hide what
     * the sender wrote; it then shows as plain text. The same rule as Apple's
     * `MentionCodec.isMentionRange`, code point for code point.
     */
    fun isMentionRange(text: String, start: Int, length: Int): Boolean {
        if (length < 2 || length > MAX_RANGE || !inBounds(start, length, text.length) || text[start] != '@') return false
        if (start > 0 && !mayPrecede(Character.codePointBefore(text, start))) return false
        var i = start + 1
        val end = start + length
        var afterLetter = false
        while (i < end) {
            val u = text[i]
            val cp: Int
            if (u.isHighSurrogate()) {
                if (i + 1 >= end || !text[i + 1].isLowSurrogate()) return false
                cp = Character.toCodePoint(u, text[i + 1]); i += 2
            } else {
                if (u.isLowSurrogate()) return false
                cp = u.code; i += 1
            }
            when (tokenClass(cp)) {
                TokenClass.LETTER -> afterLetter = true
                TokenClass.OTHER -> afterLetter = false
                TokenClass.MARK -> if (!afterLetter) return false
                TokenClass.REFUSED -> return false
            }
        }
        return true
    }

    enum class TokenClass { LETTER, MARK, OTHER, REFUSED }

    /** Blank-looking letters and marks the general categories would let through. */
    private fun isBlankLike(cp: Int): Boolean =
        cp == 0x115F || cp == 0x1160 || cp == 0x3164 || cp == 0xFFA0 || cp == 0x034F || cp == 0x17B4 || cp == 0x17B5 ||
            cp in 0x180B..0x180F || cp in 0xFE00..0xFE0F || cp in 0xE0000..0xE01EF

    /** What a code point is inside a mention token: a letter (L*), a combining mark (Mn, Mc — only after a letter), another allowed character (a digit, Nd, or `_ . -`), or refused. */
    fun tokenClass(cp: Int): TokenClass {
        if (cp == '_'.code || cp == '.'.code || cp == '-'.code) return TokenClass.OTHER
        if (isBlankLike(cp)) return TokenClass.REFUSED
        return when (Character.getType(cp).toByte()) {
            Character.UPPERCASE_LETTER, Character.LOWERCASE_LETTER, Character.TITLECASE_LETTER,
            Character.MODIFIER_LETTER, Character.OTHER_LETTER -> TokenClass.LETTER
            Character.NON_SPACING_MARK, Character.COMBINING_SPACING_MARK -> TokenClass.MARK
            Character.DECIMAL_DIGIT_NUMBER -> TokenClass.OTHER
            else -> TokenClass.REFUSED
        }
    }

    /** What may stand right before a mention's '@': whitespace (tab to carriage return, Zs, Zl, Zp) or punctuation (P*). */
    fun mayPrecede(cp: Int): Boolean {
        if (cp in 0x09..0x0D) return true
        return when (Character.getType(cp).toByte()) {
            Character.SPACE_SEPARATOR, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR,
            Character.CONNECTOR_PUNCTUATION, Character.DASH_PUNCTUATION, Character.START_PUNCTUATION,
            Character.END_PUNCTUATION, Character.INITIAL_QUOTE_PUNCTUATION, Character.FINAL_QUOTE_PUNCTUATION,
            Character.OTHER_PUNCTUATION -> true
            else -> false
        }
    }

    /**
     * The token the composer inserts for [name]: '@' and the name's allowed characters
     * ([isMentionRange]), each run of anything else written as '_', cut to [MAX_RANGE] units. A
     * name that leaves nothing becomes "@member".
     */
    fun token(name: String): String {
        val out = StringBuilder("@")
        var gap = false
        var afterLetter = false
        var i = 0
        while (i < name.length) {
            val cp = name.codePointAt(i)
            i += Character.charCount(cp)
            val cls = tokenClass(cp)
            val ok = cls == TokenClass.LETTER || cls == TokenClass.OTHER || (cls == TokenClass.MARK && afterLetter)
            if (!ok) { gap = out.length > 1; afterLetter = false; continue }
            val add = (if (gap) 1 else 0) + Character.charCount(cp)
            if (out.length + add > MAX_RANGE) break
            if (gap) out.append('_')
            out.appendCodePoint(cp)
            gap = false
            if (cls == TokenClass.LETTER) afterLetter = true else if (cls == TokenClass.OTHER) afterLetter = false
        }
        return if (out.length > 1) out.toString() else "@member"
    }

    /**
     * The mentions that may replace text on screen, in order: each one [isMentionRange], none
     * overlapping or touching the one before, at most [MAX_MENTIONS] covering at most
     * [MAX_COVERED] units. Ties keep the sender's order. Apple's `MentionCodec.valid` is the same.
     */
    fun valid(text: String, mentions: List<Mention>): List<Mention> {
        val out = ArrayList<Mention>()
        var end = -1
        var covered = 0
        for (m in mentions.sortedBy { it.start }) {
            if (m.userId.isEmpty() || !isMentionRange(text, m.start, m.length)) continue
            if (m.start <= end || covered + m.length > MAX_COVERED) continue
            out.add(m); end = m.start + m.length   // in bounds: cannot overflow
            covered += m.length
            if (out.size == MAX_MENTIONS) break
        }
        return out
    }

    /**
     * The composer's picks (user id → the "@name" inserted) placed in the text as it is now:
     * every occurrence of the inserted label counts, so editing around it keeps it, and deleting
     * it drops it.
     */
    fun locate(text: String, picked: List<Pair<String, String>>): List<Mention> {
        val found = ArrayList<Mention>()
        for ((uid, label) in picked.distinct()) {
            if (!label.startsWith("@") || label.length < 2) continue
            var i = text.indexOf(label)
            while (i >= 0) {
                val after = i + label.length
                // A whole token: not the start of a longer name.
                if (after == text.length || !(text[after].isLetterOrDigit() || text[after] == '_')) found.add(Mention(uid, i, label.length))
                i = text.indexOf(label, after)
            }
        }
        return valid(text, found)
    }

    /** The "@word" being typed at the end of [text], without the '@' — null when none. */
    fun query(text: String): String? {
        val at = text.lastIndexOf('@')
        if (at < 0 || (at > 0 && !text[at - 1].isWhitespace())) return null
        val q = text.substring(at + 1)
        return if (q.any { it.isWhitespace() } || q.length > 32) null else q
    }

    /**
     * Someone the composer may @mention: user id, the label this device shows for them
     * ([ContactTrust]), and their username (empty when unknown).
     */
    data class Candidate(val userId: String, val label: String, val username: String)

    /**
     * The token inserted for [c] (build 47): built from the USERNAME — short, already in the
     * token's characters, what people type after '@' — and only without one from the label.
     * How the mention RENDERS is never this text: it is the label this device has for the id.
     */
    fun tokenFor(c: Candidate): String = token(c.username.trim().ifEmpty { c.label })

    /** Candidates whose label or username starts with (then contains) [query], case-insensitively. */
    fun matches(query: String, candidates: List<Candidate>, limit: Int = 5): List<Candidate> {
        val q = query.lowercase()
        fun starts(c: Candidate) = c.label.lowercase().startsWith(q) || c.username.lowercase().startsWith(q)
        fun contains(c: Candidate) = c.label.lowercase().contains(q) || c.username.lowercase().contains(q)
        val first = candidates.filter(::starts).sortedBy { it.label.lowercase() }
        val then = candidates.filter { !starts(it) && contains(it) }
        return (first + then).take(limit)
    }

    /** [text] with the "@query" at its end replaced by [label] and a space. */
    fun complete(text: String, label: String): String {
        val at = text.lastIndexOf('@')
        return if (at < 0) "$text$label " else text.substring(0, at) + label + " "
    }

    /**
     * Whose @everyone counts in a server — the same rule as Apple's `EveryoneRule`: the PINNED
     * owner, and admins (roles granting Administrator or Manage Server).
     *
     * What is trusted: the pinned owner is this device's own pin (create/join flow, key backup,
     * verified sibling), never the server's list. Roles and role assignments are the SERVER's
     * word (nothing signs them), so an admin counts only when the account is in the server's
     * member list, is not one this device is holding (no trusted approval — `heldMembers`) and is
     * not blocked. A hostile host could still name an approved member an admin; that buys their
     * @everyone alerting through conversation/server mutes, never a skwod mute or a block.
     */
    const val ADMINISTRATOR = 8192L
    const val MANAGE_SERVER = 4L
    const val ADMIN_BITS = ADMINISTRATOR or MANAGE_SERVER

    /** A server role as the gate sees it: its id, its permission bits, and whether it is the default (@everyone) role. */
    data class RoleBits(val id: String, val permissions: Long, val isDefault: Boolean)

    /**
     * What counts for the @everyone gate: only roles the server ASSIGNED to the member. The
     * default (@everyone) role is everybody's, so its bits never make anyone an admin here.
     */
    fun everyonePermissions(memberRoleIds: Collection<String>, roles: List<RoleBits>): Long =
        roles.filter { !it.isDefault && it.id in memberRoleIds }.fold(0L) { acc, r -> acc or r.permissions }

    /** [held] null = this device could not say whom it is holding: then no admin counts, only the pinned owner (fail closed). */
    fun everyoneSenders(pinnedOwner: String?, memberPermissions: Map<String, Long>, held: Set<String>?, blocked: Set<String>): Set<String> {
        val out = if (held == null) mutableSetOf()
            else memberPermissions.filter { (id, p) -> id.isNotEmpty() && p and ADMIN_BITS != 0L && id !in held && id !in blocked }.keys.toMutableSet()
        if (!pinnedOwner.isNullOrEmpty() && pinnedOwner !in blocked) out.add(pinnedOwner)
        return out
    }

    /** Is [senderId]'s @everyone honoured, given [allowed] ([everyoneSenders]) and the pinned owner? */
    fun everyoneHonoured(senderId: String?, allowed: Set<String>, pinnedOwner: String? = null): Boolean {
        if (senderId.isNullOrEmpty()) return false
        return senderId in allowed || (pinnedOwner != null && senderId == pinnedOwner)
    }

    /**
     * Does this message call on me? A mention of my id, an honoured @everyone, or a reply to a
     * message of mine. Never my own message.
     */
    fun mentionsMe(decoded: Decoded, me: String, senderId: String?, everyoneHonoured: Boolean, replyToMine: Boolean = false): Boolean {
        if (me.isEmpty() || senderId == me) return false
        return decoded.mentions.any { it.userId == me } || (decoded.everyone && everyoneHonoured) || replyToMine
    }
}

/**
 * A mention of me ALWAYS alerts, with sound, even in a muted conversation or server; only a
 * muted skwod or a blocked sender silences it (Do Not Disturb still applies, as for any alert).
 */
object MentionAlert {
    /** The mute [AlertPolicy] is given for this message. */
    fun muted(conversationMuted: Boolean, skwodMuted: Boolean, mentioned: Boolean): Boolean =
        skwodMuted || (conversationMuted && !mentioned)

    fun alerts(conversationMuted: Boolean, skwodMuted: Boolean, mentioned: Boolean, senderBlocked: Boolean): Boolean =
        !senderBlocked && !muted(conversationMuted, skwodMuted, mentioned)

    /** "Sam mentioned you in #general"; previews off or app lock on: "You were mentioned". */
    fun title(who: String, where: String, redacted: Boolean): String = if (redacted) "You were mentioned" else "$who mentioned you in $where"
}

/**
 * Unseen mentions of me, per skwod and conversation ("channel:…" / "dm:…"): the red "@ n" on
 * channel rows, server tiles and the DM list, cleared when the conversation is opened. Each
 * message counts once ([counted], bounded) — the same ledger as Apple's `MentionBadgeLedger`.
 * Immutable; [AppModel] keeps it in its own preferences.
 */
data class MentionBadgeLedger(val counts: Map<String, Map<String, Int>> = emptyMap(), val counted: List<String> = emptyList()) {
    companion object {
        const val MAX_COUNTED = 2000

        fun fromJson(s: String?): MentionBadgeLedger = try {
            val o = org.json.JSONObject(s ?: "")
            val c = o.optJSONObject("counts") ?: org.json.JSONObject()
            val counts = c.keys().asSequence().associateWith { wid ->
                val t = c.optJSONObject(wid) ?: org.json.JSONObject()
                t.keys().asSequence().associateWith { t.optInt(it, 0).coerceAtLeast(0) }.filterValues { it > 0 }
            }.filterValues { it.isNotEmpty() }
            val ids = o.optJSONArray("counted")
            MentionBadgeLedger(counts, ids?.let { a -> (0 until a.length()).mapNotNull { a.opt(it) as? String } } ?: emptyList())
        } catch (_: Exception) { MentionBadgeLedger() }
    }

    fun toJson(): String = org.json.JSONObject()
        .put("counts", org.json.JSONObject().apply { counts.forEach { (w, t) -> put(w, org.json.JSONObject(t)) } })
        .put("counted", org.json.JSONArray(counted)).toString()

    /** The ids not counted before are added to [topic]'s count. */
    fun add(ids: List<String>, topic: String, workspaceId: String): MentionBadgeLedger {
        val seen = counted.toHashSet()
        val fresh = ids.filter { it.isNotEmpty() && it !in seen }.distinct()
        if (fresh.isEmpty() || topic.isEmpty() || workspaceId.isEmpty()) return this
        val topics = counts[workspaceId].orEmpty()
        val next = counts + (workspaceId to (topics + (topic to (topics[topic] ?: 0) + fresh.size)))
        return MentionBadgeLedger(next, (counted + fresh).takeLast(MAX_COUNTED))
    }

    fun clear(topic: String, workspaceId: String): MentionBadgeLedger {
        val topics = counts[workspaceId] ?: return this
        if (topic !in topics) return this
        val left = topics - topic
        return copy(counts = if (left.isEmpty()) counts - workspaceId else counts + (workspaceId to left))
    }

    fun count(topic: String, workspaceId: String): Int = counts[workspaceId]?.get(topic) ?: 0
    fun count(topics: Collection<String>, workspaceId: String): Int = topics.sumOf { count(it, workspaceId) }
}
