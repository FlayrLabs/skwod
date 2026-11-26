package io.skwod.app

import org.json.JSONObject

/**
 * Build 49: what is new in a conversation since this device last read it — the "New" divider, the
 * bar above the list, the "↓ N new" pill and where a conversation opens. The same rules as the
 * Apple app's `UnreadRule` (UnreadRules.swift). Pure (no android.*, no FFI): unit-tested on the
 * JVM (`Build49Test`).
 */

/** Where this device last read a conversation: the newest message on screen at the bottom.
 *  Id AND time: the message may later be outside the loaded page, or deleted. */
data class ReadMarker(val messageId: String, val createdAt: Long) {
    fun encode(): String = JSONObject().put("messageId", messageId).put("createdAt", createdAt).toString()

    companion object {
        fun decode(json: String?): ReadMarker? = try {
            if (json.isNullOrBlank()) null
            else JSONObject(json).let { ReadMarker(it.getString("messageId"), it.getLong("createdAt")) }
        } catch (_: Exception) { null }
    }
}

/** What the rules need to know about one row. */
data class UnreadItem(val id: String, val createdAt: Long, val mine: Boolean, val system: Boolean = false)

object UnreadRule {
    /** The encrypted-cache key (one skwod's cache, per conversation). */
    fun storageKey(workspaceId: String, conversationId: String) = "$workspaceId|read.$conversationId"

    fun counts(item: UnreadItem) = !item.mine && !item.system

    /** Index of the first unread row, or null. No marker (never opened here) = nothing unread. */
    /**
     * Build 51: what was unread when the conversation was OPENED — against the marker as it was
     * then, counting only rows written before that moment. Rows a catch-up brings in after the list
     * was already showing (a cold launch opens on the cache first) belong to the bar and the
     * divider, not to "read on arrival". (first index, count), or null.
     */
    fun atOpen(items: List<UnreadItem>, markerAtOpen: ReadMarker?, openedAt: Long): Pair<Int, Int>? {
        val before = items.withIndex().filter { it.value.createdAt <= openedAt }
        val rows = before.map { it.value }
        val first = firstUnreadIndex(rows, markerAtOpen) ?: return null
        return before[first].index to unreadCount(rows, markerAtOpen)
    }

    fun firstUnreadIndex(items: List<UnreadItem>, marker: ReadMarker?): Int? {
        if (marker == null) return null
        val at = items.indexOfFirst { it.id == marker.messageId }
        val start = if (at >= 0) at + 1 else items.indexOfFirst { it.createdAt > marker.createdAt }.let { if (it < 0) items.size else it }
        if (start >= items.size) return null
        // Something I sent after the marker means I was here then.
        val lastMine = (start until items.size).lastOrNull { items[it].mine }
        val from = lastMine?.plus(1) ?: start
        return (from until items.size).firstOrNull { counts(items[it]) }
    }

    fun unreadCount(items: List<UnreadItem>, marker: ReadMarker?): Int {
        val first = firstUnreadIndex(items, marker) ?: return 0
        return items.subList(first, items.size).count(::counts)
    }

    /** Never moves backwards. */
    fun advanced(marker: ReadMarker?, item: UnreadItem): ReadMarker {
        val next = ReadMarker(item.id, item.createdAt)
        return if (marker == null || item.createdAt >= marker.createdAt) next else marker
    }

    /** Rows from others after the last row the reader had in view at the bottom. */
    fun newBelow(items: List<UnreadItem>, lastSeenId: String?): Int {
        if (lastSeenId == null) return 0
        val at = items.indexOfFirst { it.id == lastSeenId }
        if (at < 0) return 0
        return items.subList(at + 1, items.size).count(::counts)
    }

    fun barText(count: Int, since: String) = "$count ${if (count == 1) "new message" else "new messages"} since $since"
}

/** Build 49: what a server name may be — the core's rule (trimmed, 1 to 100 characters, one
 *  line, no direction overrides), so the app says why before asking. */
object ServerName {
    const val MAX = 100
    const val MAX_BYTES = 400

    fun problem(raw: String): String? {
        val name = raw.trim()
        // Unicode scalars and UTF-8 bytes — exactly what the core counts.
        if (name.isEmpty() || name.codePointCount(0, name.length) > MAX || name.toByteArray(Charsets.UTF_8).size > MAX_BYTES) return "A server name needs 1 to $MAX characters."
        // The core's rule exactly: control, format (Cf) and blank-looking characters are refused.
        val blank = setOf(0x115F, 0x1160, 0x2800, 0x3164, 0xFFA0, 0x034F, 0x17B4, 0x17B5)
        fun ignorable(c: Int) = c in 0x180B..0x180F || c == 0x2065 || c in 0xFE00..0xFE0E || c in 0xFFF0..0xFFF8 || c in 0xE0000..0xE0FFF
        fun invisibleOrBlank(c: Int) = Character.isISOControl(c) || Character.getType(c) == Character.FORMAT.toInt() || c in blank ||
            ignorable(c) || c == 0x2028 || c == 0x2029
        fun emojiBase(c: Int) = !(Character.isLetterOrDigit(c) || Character.isWhitespace(c) || invisibleOrBlank(c) || c == 0xFE0F) &&
            (c >= 0x2000 || c in listOf('#'.code, '*'.code, 0xA9, 0xAE))
        val cps = name.codePoints().toArray()
        for ((i, c) in cps.withIndex()) {
            // The emoji presentation selector only right after a visible emoji base ("❤️").
            if (c == 0xFE0F) { if (i > 0 && emojiBase(cps[i - 1])) continue; return "A server name can't contain line breaks, control or invisible characters." }
            if (invisibleOrBlank(c)) return "A server name can't contain line breaks, control or invisible characters."
        }
        return null
    }
}

/** Build 49: what this device takes from the state one of its OWN other devices hands over (the
 *  Apple app's `SiblingRules`). The core merged the verifications and lists the contacts it
 *  holds under other keys (`mismatched`): skipped entirely here. */
object SiblingRules {
    /** A newly linked device asks its siblings for their state until one has handed it over: the
     *  sibling may be away, or send before its snapshot is here (then nothing can be taken).
     *  (A sibling answers one device at most every 10 minutes.) */
    const val REQUEST_GAP_MS = 11 * 60_000L
    /** Per launch, at most (a sibling too old to answer is not asked for ever). */
    const val MAX_REQUESTS = 6

    fun mayRequest(answered: Boolean, asks: Int, lastAsk: Long?, now: Long): Boolean =
        !answered && asks < MAX_REQUESTS && (lastAsk == null || now - lastAsk >= REQUEST_GAP_MS)

    /** Did this contact book answer the request? Not when nobody in it could be taken. */
    fun answers(book: Map<String, Contact>, vouched: Collection<String>): Boolean = book.isEmpty() || vouched.isNotEmpty()

    const val MAX_AVATAR_BYTES = 96 * 1024
    const val MAX_BATCH_BYTES = 120 * 1024
    const val SEND_BUDGET = 110_000

    /** A name the user set here (known/verified) wins; a synced one never counts above KNOWN,
     *  and only UNVERIFIED when it collides with someone the user knows or has unusual characters.
     *  Only users the sender's snapshot vouches for, and that agree with this device, are taken. */
    fun mergedContact(local: Contact?, synced: Contact, vouched: Boolean, mismatched: Boolean,
                      book: Map<String, Contact>, roster: Map<String, String> = emptyMap()): Contact? {
        if (mismatched || !vouched || synced.name.isEmpty()) return null
        if (local != null && local.level >= TrustLevel.KNOWN) return null
        val suspicious = ContactTrust.collides(synced.userId, synced.name, book, roster) || NameSkeleton.isUnusual(synced.name)
        // KNOWN only for someone the sibling's user made known themself; a verified-only entry
        // (known == false) stays UNVERIFIED here — the core decides VERIFIED, and un-verifying
        // then returns it to UNVERIFIED.
        val known = !suspicious && synced.explicitlyKnown
        val level = if (known) TrustLevel.KNOWN else TrustLevel.UNVERIFIED
        val merged = Contact(synced.userId, synced.name, maxOf(local?.level ?: TrustLevel.UNVERIFIED, level), known || (local?.known == true))
        return if (merged == local) null else merged
    }

    /** The whole synced book, entry by entry against the growing result (local entries first). */
    fun mergedBook(local: Map<String, Contact>, synced: Map<String, Contact>, vouched: Set<String>, mismatched: Set<String>,
                   roster: Map<String, String> = emptyMap()): Map<String, Contact> {
        val book = LinkedHashMap(local)
        for (uid in synced.keys.sorted().take(2000)) {
            if (uid.isEmpty() || uid.length > 128) continue
            val c = synced[uid] ?: continue
            mergedContact(book[uid], c.copy(userId = uid), uid in vouched, uid in mismatched, book, roster)?.let { book[uid] = it }
        }
        return book
    }

    data class AvatarEntry(val key: String, val img: String?, val ts: Long)

    /** Well-formed keys; a `user:` key only for a vouched, agreeing user; newer than held or
     *  cleared here; a picture within the caps and decodable ([acceptable]) — or no picture, a
     *  clear, which also wins when newer. Value: (bytes or null for a clear, ts). */
    fun acceptedAvatars(entries: List<AvatarEntry>, vouched: Set<String>, mismatched: Set<String>, heldTs: Map<String, Long>, now: Long,
                        decode: (String) -> ByteArray?, acceptable: (ByteArray) -> Boolean): Map<String, Pair<ByteArray?, Long>> {
        val out = LinkedHashMap<String, Pair<ByteArray?, Long>>()
        var total = 0
        for (e in entries.take(64)) {
            if (!(e.key.startsWith("user:") || e.key.startsWith("server:") || e.key.startsWith("skwod:")) || e.key.length > 200) continue
            if (e.key.startsWith("user:")) { val u = e.key.removePrefix("user:"); if (u in mismatched || u !in vouched) continue }
            if (e.ts <= 0 || e.ts > now + 5 * 60 * 1000 || (heldTs[e.key] ?: 0) >= e.ts || (out[e.key]?.second ?: 0) >= e.ts) continue
            val img = e.img
            if (img.isNullOrEmpty()) { out[e.key] = null to e.ts; continue }
            if (img.length > MAX_AVATAR_BYTES * 4 / 3 + 4) continue
            val bytes = decode(img) ?: continue
            if (bytes.size > MAX_AVATAR_BYTES || total + bytes.size > MAX_BATCH_BYTES || !acceptable(bytes)) continue
            total += bytes.size
            out[e.key] = bytes to e.ts
        }
        return out
    }

    fun batches(entries: List<AvatarEntry>, first: String?, limit: Int = SEND_BUDGET, maxBatches: Int = 8): List<List<AvatarEntry>> {
        val ordered = entries.sortedWith(compareByDescending<AvatarEntry> { it.key == first }.thenByDescending { it.ts })
        val out = mutableListOf<List<AvatarEntry>>()
        var current = mutableListOf<AvatarEntry>()
        var size = 0
        for (e in ordered) {
            val len = e.img?.length ?: 0   // a clear (no picture) travels too
            val n = len + e.key.length + 32
            if (len * 3 / 4 > MAX_AVATAR_BYTES || n > limit) continue
            if (size + n > limit && current.isNotEmpty()) {
                out.add(current); if (out.size == maxBatches) return out
                current = mutableListOf(); size = 0
            }
            current.add(e); size += n
        }
        if (current.isNotEmpty() && out.size < maxBatches) out.add(current)
        return out
    }
}

/** Build 49: where a name appears decides its form. Styled rows show the plain name with a mark
 *  beside it; text-only and security-relevant places keep the words ("(unverified)"). */
enum class NameForm { TEXT, BADGE }

enum class NameSurface(val form: NameForm) {
    NOTIFICATION(NameForm.TEXT), INCOMING_CALL(NameForm.TEXT), DIALOG_TITLE(NameForm.TEXT), JOIN_CONFIRMATION(NameForm.TEXT),
    GROUP_CONFIRMATION(NameForm.TEXT), KICK_BAN_DIALOG(NameForm.TEXT), SECURITY_NOTICE(NameForm.TEXT), TYPING(NameForm.TEXT),
    MENTION_PICKER(NameForm.TEXT), REPLY_PREVIEW(NameForm.TEXT), ACTION_SHEET(NameForm.TEXT), APPROVAL_ROW(NameForm.TEXT),
    BLOCK_REPORT_TARGET(NameForm.TEXT),
    MESSAGE_HEADER(NameForm.BADGE), MEMBER_ROW(NameForm.BADGE), DM_ROW(NameForm.BADGE), MENTION_CHIP(NameForm.BADGE), PROFILE_CARD(NameForm.BADGE),
}

/** Build 49: the `contacts.v1` sibling payload, the same format as the Apple app's (documented
 *  in core `b49.rs`): a JSON object, user id → {"name", "level": "unverified"|"known"|"verified",
 *  "known"?}. */
object SiblingBook {
    fun encode(book: Map<String, Contact>): String {
        val o = org.json.JSONObject()
        for ((id, c) in book) {
            val e = org.json.JSONObject().put("name", c.name).put("level", c.level.name.lowercase())
            c.known?.let { e.put("known", it) }
            o.put(id, e)
        }
        return o.toString()
    }

    fun decode(json: String): Map<String, Contact> {
        val o = try { org.json.JSONObject(json) } catch (_: Exception) { return emptyMap() }
        val out = LinkedHashMap<String, Contact>()
        for (id in o.keys()) {
            val e = o.optJSONObject(id) ?: continue
            if (id.isEmpty() || id.length > 128) continue
            val level = when (e.optString("level")) { "known" -> TrustLevel.KNOWN; "verified" -> TrustLevel.VERIFIED; else -> TrustLevel.UNVERIFIED }
            out[id] = Contact(id, e.optString("name"), level, if (e.has("known")) e.optBoolean("known") else null)
        }
        return out
    }
}

/** Build 49: one gated write of a per-workspace store. The workspace is fixed up front
 *  ([expected], or the current one); nothing is written when the current workspace or the
 *  loaded one differs — before the change, or after it (a switch during the call). Returns the
 *  new value written, or null. */
object GatedWrite {
    fun <B : Any> apply(expected: String, current: () -> String?, loadedFor: () -> String?, value: B,
                        change: (B) -> B, write: (String, B) -> Unit): B? {
        if (expected.isEmpty() || current() != expected || loadedFor() != expected) return null
        val next = change(value)
        if (next === value) return null
        if (current() != expected || loadedFor() != expected) return null
        write(expected, next)
        return next
    }
}

/** Build 49: one step bound to the skwod it started in: [call] (the core), then — only if the
 *  binding still holds — [after] (anything that writes). Returns whether [after] ran. */
object BoundStep {
    suspend fun <T : Any> run(asked: T, now: () -> T?, call: suspend () -> Unit, after: suspend () -> Unit): Boolean {
        call()
        if (!Asked.holds(asked, now())) return false
        after()
        return true
    }
}

/** Build 49: "Clear all messages", captured when the confirmation OPENS (the binding, the
 *  servers, the skwod's name); confirming goes ahead only in that very binding, as its owner. */
data class ClearAllRequest<T : Any>(val asked: T, val serverIds: List<String>, val skwodName: String) {
    fun mayProceed(now: T?, isInstanceOwner: Boolean): Boolean = isInstanceOwner && Asked.holds(asked, now) && serverIds.isNotEmpty()
}
