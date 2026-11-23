package io.skwod.app

/**
 * Small decisions the app makes in several places, kept pure (no android.*, no FFI) so each is
 * unit-tested on the JVM: what notifies, which ring to present, when a session token is rotated,
 * how retries back off, and what an upload refusal says.
 */

/**
 * Does a decrypted message deserve a notification?
 *
 * Only real chat from someone else does. The server cannot tell kinds of message apart (it sees
 * ciphertext, and no traffic class), so every message produces the same realtime event; the
 * decision is made HERE, after decrypting. At run time the notifier asks the core
 * (`messageNotifies`); this is the same rule in Kotlin — the tested fallback and the source of
 * the one-line preview. Quiet kinds are exactly: game, like, comment, avatar, addr, sys.
 */
/**
 * What the app does, by itself, when a message arrives while it is running — and when one of
 * the user's own is accepted by the server. The same rule as the Apple apps' `MessageAlert`:
 * a chat you are looking at is silent; anything else makes ONE sound — the app's own while it
 * is in front, the notification's when it is not — and nothing under Do Not Disturb.
 */
object AlertPolicy {
    data class Incoming(
        /** Written by this account (here or on another of its devices). */
        val fromSelf: Boolean = false,
        val blocked: Boolean = false,
        /** The conversation is muted or snoozed (no build has such a setting yet: always false). */
        val muted: Boolean = false,
        /** The user's own status is Do Not Disturb. */
        val doNotDisturb: Boolean = false,
        /** The app is in front. */
        val appActive: Boolean = false,
        /** The conversation is the one on screen (and the app is in front). */
        val onScreen: Boolean = false,
        /** Settings → "Sound for new messages". */
        val soundOn: Boolean = true,
        /** When the app last played its received sound (ms; 0 = never), and now. */
        val lastSoundAt: Long = 0,
        val now: Long = 0,
    )

    data class Outcome(val banner: Boolean = false, val bannerSound: Boolean = false, val inAppSound: Boolean = false)

    val NOTHING = Outcome()

    /** At most one received sound per this many milliseconds. */
    const val BURST_MS = 1000L

    fun received(m: Incoming): Outcome {
        if (m.fromSelf || m.blocked || m.muted) return NOTHING
        if (m.doNotDisturb) return NOTHING
        if (m.appActive && m.onScreen) return NOTHING
        if (m.appActive) {
            val rested = m.lastSoundAt <= 0 || m.now < m.lastSoundAt || m.now - m.lastSoundAt >= BURST_MS
            return Outcome(banner = true, bannerSound = false, inAppSound = m.soundOn && rested)
        }
        return Outcome(banner = true, bannerSound = m.soundOn, inAppSound = false)
    }

    /** The sent sound: when the server ACCEPTED something the user composed — not on tap, and
     *  not for what the app sends by itself (likes, game moves, avatars). */
    fun sentSound(composedWaiting: Int, accepted: Int, soundOn: Boolean): Boolean =
        soundOn && composedWaiting > 0 && accepted > 0
}

/**
 * What the user muted in ONE skwod, on this device: conversations (`channel:<id>` / `dm:<id>`)
 * and the skwod as a whole — for an hour, eight, a day, or until unmuted. Never sent anywhere.
 * The Apple apps' `MuteList`, in Kotlin. Immutable: a change returns a new list.
 */
data class MuteList(val until: Map<String, Long> = emptyMap()) {
    enum class Duration(val millis: Long?, val label: String) {
        HOUR(3_600_000L, "For 1 hour"),
        EIGHT_HOURS(8 * 3_600_000L, "For 8 hours"),
        DAY(24 * 3_600_000L, "For 24 hours"),
        FOREVER(null, "Until I turn it back on"),
    }

    companion object {
        /** The key under which the whole skwod is muted. */
        const val SKWOD = "skwod"
        /** `until` of a mute with no end. */
        const val FOREVER = -1L

        private fun holds(until: Long, now: Long) = until == FOREVER || until > now

        /** From the stored JSON (`{"key": untilMs}`); anything unreadable is "nothing muted". */
        fun parse(json: String?): MuteList = try {
            val o = org.json.JSONObject(json ?: "{}")
            MuteList(o.keys().asSequence().associateWith { o.getLong(it) })
        } catch (_: Exception) { MuteList() }
    }

    fun mute(key: String, duration: Duration, now: Long): MuteList {
        if (key.isEmpty()) return this
        val live = until.filterValues { holds(it, now) }
        return MuteList(live + (key to (duration.millis?.let { now + it } ?: FOREVER)))
    }

    fun unmute(key: String): MuteList = MuteList(until - key)

    /** Is exactly this key muted right now? */
    fun holds(key: String, now: Long): Boolean = until[key]?.let { holds(it, now) } ?: false

    /** Is a message in [scope] muted — the conversation itself, or the whole skwod? */
    fun isMuted(scope: String, now: Long): Boolean = holds(scope, now) || holds(SKWOD, now)

    /** Does a call ring? A muted conversation does not silence calls; a muted skwod does. */
    fun callsRing(now: Long): Boolean = !holds(SKWOD, now)

    fun toJson(): String = org.json.JSONObject(until.mapValues { it.value }).toString()
}

object NotifyPolicy {
    private const val STX = '\u0002'
    private val QUIET = listOf("skwod/game|", "skwod/like|", "skwod/comment|", "skwod/avatar|", "skwod/addr|", "skwod/sys|")

    /** The `skwod/<kind>|` tag a body starts with (after an optional STX), or null for plain text. */
    fun tag(body: String): String? {
        val start = if (body.isNotEmpty() && body[0] == STX) 1 else 0
        if (!body.startsWith("skwod/", start)) return null
        val bar = body.indexOf('|', start)
        if (bar < 0 || bar - start > 24) return null
        return body.substring(start, bar + 1)
    }

    /** App plumbing that rides the channel but is never announced. */
    fun isQuiet(body: String): Boolean = tag(body) in QUIET

    /** The rule for a decrypted body alone. */
    fun notifies(body: String): Boolean = body.isNotEmpty() && !isQuiet(body)

    /**
     * The whole decision for one message. [body] null = it could not be decrypted (yet): that is
     * still a message from someone, announced generically.
     */
    fun shouldNotify(body: String?, authorId: String?, me: String, isDeleted: Boolean,
                     isSystem: Boolean = false, isUndecryptable: Boolean = false, isBlocked: (String) -> Boolean = { false },
                     coreNotifies: (String) -> Boolean = ::notifies): Boolean {
        if (isDeleted) return false
        // A row the core wrote itself (a notice, a "couldn't decrypt" placeholder) is not a
        // message from anyone. That is a fact about the ROW — its flags — never read off the
        // text or the author id, which a sender controls.
        if (isSystem || isUndecryptable) return false
        if (authorId == null || authorId == me || authorId == "__me__") return false
        // Nobody this account blocked ever reaches a notification.
        if (isBlocked(authorId)) return false
        if (body == null) return true
        return notifies(body) && coreNotifies(body)
    }

    /**
     * [items] without the ones whose author this account blocked. Every place that raises a DM
     * or channel notification filters with this BEFORE notifying (and before listing the
     * conversation): DM events, live `message` events, the catch-up after a reconnect.
     */
    fun <T> withoutBlocked(items: List<T>, author: (T) -> String?, isBlocked: (String) -> Boolean): List<T> =
        items.filter { item -> author(item).let { it == null || !isBlocked(it) } }

    /** What a notification may say, and the thread it is filed under. */
    data class Shape(val title: String, val text: String, val topic: String)

    const val GENERIC_TITLE = "Skwod"
    const val GENERIC_TEXT = "New message"
    const val GENERIC_TOPIC = "messages"

    /**
     * Is every notification reduced to the generic form? Yes when the user hid previews, and
     * yes whenever app lock is ENABLED — the persisted setting, not whether the lock happens to
     * be closed right now. An app that is unlocked but in the background, or a process the
     * connection service started with no UI at all, has no trustworthy "is locked" to ask:
     * with the lock on, what a notification shows must not depend on it. [lockedNow] is taken
     * only to make that explicit — it is not consulted.
     */
    @Suppress("UNUSED_PARAMETER")
    fun redacted(hidePreviews: Boolean, appLockEnabled: Boolean, lockedNow: Boolean = false): Boolean = hidePreviews || appLockEnabled

    /**
     * The last gate before anything is posted. With app lock on: no sender, no text, and one
     * generic thread for everything (a per-conversation thread would still say how many
     * conversations are active, and its id is derived from the conversation's).
     */
    fun shape(title: String, text: String, topic: String, appLockEnabled: Boolean,
              hidePreviews: Boolean = false, kind: Text = Text.PERSONAL): Shape = when {
        appLockEnabled -> Shape(GENERIC_TITLE, GENERIC_TEXT, GENERIC_TOPIC)
        // "Hide message content": whatever the caller built, text that names someone or
        // quotes something is not shown. (The topic only keys the notification; it is not
        // displayed.)
        hidePreviews && kind == Text.PERSONAL -> Shape(GENERIC_TITLE, GENERIC_TEXT, topic)
        else -> Shape(title, text, topic)
    }

    /** What a notification's text is made of — every caller of [Notifications.message] says. */
    enum class Text {
        /** Names someone or something of the user's, or quotes a message. */
        PERSONAL,
        /** A sentence the app wrote that names nobody. */
        FIXED,
    }

    /** Who an incoming call is shown as: nobody in particular while app lock is on. */
    fun callLabel(label: String, appLockEnabled: Boolean): String = if (appLockEnabled) "Skwod call" else label

    /** What a body looks like in one line of a notification; null when it has nothing to show. */
    fun preview(body: String): String? = when (tag(body)) {
        null -> if (body.isNotEmpty() && body[0].code < 0x20) null else Mentions.visible(body).take(240).ifBlank { null }
        "skwod/attach|" -> "Sent an attachment"
        "skwod/music|" -> "Shared a song"
        "skwod/feed|" -> "Posted to the feed"
        "skwod/story|" -> "Added a story"
        else -> null
    }
}

/** A ring as the server describes it (`ring` event, or `pendingRings()`). */
data class Ring(val serverId: String, val channelId: String, val fromUserId: String, val ringId: String, val expiresAt: Long)

object RingPolicy {
    /** A ring past its `expires_at` is over: never present it, never keep it. 0 = no deadline given. */
    fun isLive(expiresAt: Long, now: Long): Boolean = expiresAt <= 0 || expiresAt > now

    /**
     * The deadline this app honours for a ring: the server's `expires_at`, but never later than
     * now + the app's own ring duration ([cap]). `expires_at` is a value the server reports — it
     * may end a ring early, it can never keep one ringing (or make it look more "current" than
     * another skwod's) beyond what the app itself allows.
     */
    fun clampExpiry(expiresAt: Long, now: Long, cap: Long): Long =
        if (expiresAt <= 0) now + cap else minOf(expiresAt, now + cap)

    /** How long the incoming-call UI may stay up: until the clamped deadline. */
    fun ringFor(expiresAt: Long, now: Long, cap: Long): Long = (clampExpiry(expiresAt, now, cap) - now).coerceIn(0, cap)

    /** What to do with everything that is ringing across the signed-in skwods. */
    sealed class Decision<out T> {
        object None : Decision<Nothing>()
        /** Exactly one skwod is ringing: present that call. */
        data class Single<T>(val workspace: T, val ring: Ring) : Decision<T>()
        /** More than one skwod is ringing: the USER says which ("Who's calling?"). One entry per skwod. */
        data class Ambiguous<T>(val choices: List<Pair<T, Ring>>) : Decision<T>()
    }

    /**
     * Never let a server-reported value choose the call. Live rings are grouped by skwod (the
     * first one listed for each); one skwod → that call; several → the user picks. Nothing here
     * compares `expires_at` between skwods.
     */
    fun <T> decide(rings: List<Pair<T, Ring>>, now: Long): Decision<T> {
        val perWorkspace = LinkedHashMap<T, Ring>()
        for ((w, r) in rings) if (isLive(r.expiresAt, now)) perWorkspace.putIfAbsent(w, r)
        return when (perWorkspace.size) {
            0 -> Decision.None
            1 -> perWorkspace.entries.first().let { Decision.Single(it.key, it.value) }
            else -> Decision.Ambiguous(perWorkspace.map { it.key to it.value })
        }
    }

    /** Does a `ring_cancel` (which may or may not name the ring) end the ring on screen? */
    fun cancels(current: Ring?, channelId: String, ringId: String?, serverId: String? = null): Boolean {
        current ?: return false
        if (!ringId.isNullOrEmpty() && current.ringId.isNotEmpty()) return ringId == current.ringId
        if (channelId.isNotEmpty() && current.channelId.isNotEmpty()) return channelId == current.channelId
        return !serverId.isNullOrEmpty() && serverId == current.serverId
    }
}

object SessionPolicy {
    const val ROTATE_AFTER_MS = 7L * 24 * 60 * 60 * 1000

    /**
     * Rotate at launch when the stored token is about a week old. [issuedAt] 0 = stored by a
     * build that did not record it: old enough by definition. A clock that went backwards is
     * treated as "unknown age" too.
     */
    fun shouldRotate(issuedAt: Long, now: Long): Boolean =
        issuedAt <= 0 || issuedAt > now || now - issuedAt >= ROTATE_AFTER_MS
}

object Backoff {
    /** [attempts] waits, doubling from [baseMs] and capped at [maxMs]. */
    fun delays(attempts: Int, baseMs: Long, maxMs: Long): List<Long> =
        (0 until attempts.coerceAtLeast(0)).map { i -> (baseMs shl i.coerceAtMost(20)).coerceIn(baseMs, maxMs) }
}

/** What to tell the user when the blob store refuses an upload (`POST /api/blobs`). */
object BlobErrors {
    const val GENERIC = "Upload failed — check your connection."

    /**
     * 403 / 413 / 507 carry a sentence written for the user in the JSON body's `error`; show it.
     * [errorField] is that field as parsed by the caller (null when absent or unparseable).
     */
    fun message(status: Int, errorField: String?): String {
        val sentence = errorField?.trim()?.takeIf { it.length in 1..300 }
        return when (status) {
            403 -> sentence ?: "You can't upload files here yet — join a server on this Skwod first."
            413 -> sentence ?: "You've used all the file storage this Skwod gives each member. Delete some attachments and try again."
            507 -> sentence ?: "This Skwod's host is almost out of disk space, so it can't take new files right now."
            429 -> "Too many uploads at once — wait a minute and try again."
            else -> GENERIC
        }
    }

    /** The `error` string of a JSON error body, or null. */
    fun errorField(body: String?): String? = try {
        if (body.isNullOrBlank()) null else org.json.JSONObject(body).optString("error").takeIf { it.isNotEmpty() }
    } catch (_: Exception) { null }
}

/** What `checkInvite` said, as a sentence for the connect screen (null = nothing to report). */
object InviteProblems {
    fun message(valid: Boolean, reason: String?): String? = if (valid) null else when (reason) {
        "expired" -> "This invite has expired. Ask your host for a fresh one."
        "used" -> "This invite has already been used or was withdrawn. Ask your host for a fresh one."
        else -> "This Skwod doesn't know that invite. Check the link, or ask your host for a fresh one."
    }
}

/** A conversation window: pages loaded with "load older" in front of the live (newest) window. */
object HistoryWindow {
    /** How many cached messages one "load older" reads. */
    const val PAGE = 100

    /**
     * [older] pages followed by the [fresh] window, chronological, each message once. Where both
     * have a message the fresh copy wins (it carries later edits and deletions).
     */
    fun <T> merge(older: List<T>, fresh: List<T>, id: (T) -> String, at: (T) -> Long): List<T> {
        if (older.isEmpty()) return fresh
        val live = fresh.mapTo(HashSet()) { id(it) }
        val seen = HashSet<String>()
        return (older.filter { id(it) !in live && seen.add(id(it)) } + fresh).sortedBy(at)
    }

    /** What to show when a send failed: the core's own sentence when it has one (message too big). */
    fun sendError(detail: String?, fallback: String): String = detail?.trim()?.takeIf { it.isNotEmpty() } ?: fallback
}

/** Size limits for attachments: what may be fetched at all, and what may be fetched unasked. */
object AttachmentLimits {
    /**
     * What every host allowed per file before that became the host's setting ([UploadLimit]) —
     * still the floor of what is downloaded, and the limit of a host that does not say.
     */
    const val MAX_BYTES = 100L * 1024 * 1024
    /** The most that is ever fetched WITHOUT the user asking for it. */
    const val AUTO_MAX_BYTES = 10L * 1024 * 1024

    class TooLarge(val limit: Long) : java.io.IOException("larger than $limit bytes")

    /** A descriptor's declared size is the sender's claim: refuse an impossible or oversized one before fetching. */
    fun acceptable(declaredSize: Long, cap: Long = UploadLimit.downloadCap()): Boolean = declaredSize in 0..cap

    /**
     * The most ciphertext a file of [plainSize] bytes can be: the padding to a size bucket (about
     * 5 %, at least one small bucket) plus IV and MAC. Generous on purpose — it bounds, it does
     * not validate (the digest does that).
     */
    fun maxCiphertext(plainSize: Long): Long = plainSize.coerceIn(0, UploadLimit.downloadCap()).let { it + it / 8 + 4096 }

    /** A response that announces more than [cap] bytes is refused before a byte of it is read. */
    fun contentLengthOk(contentLength: Long, cap: Long): Boolean = contentLength < 0 || contentLength <= cap

    /**
     * May this attachment be downloaded without the user tapping it?
     *
     * In the FEED: never, whatever its size. A download is made with the viewer's session, so
     * fetching as posts scroll into view would tell the host who looked at which post and when;
     * the feed shows the inline thumbnail and fetches on tap, like chat. Elsewhere only pictures,
     * and only small ones on a metered connection.
     */
    fun mayAutoDownload(kind: String, declaredSize: Long, inFeed: Boolean, metered: Boolean): Boolean {
        if (inFeed) return false
        // The fixed bound, not the host's upload limit: nothing a server says about its
        // limit makes this app fetch more than this without being asked.
        if (kind != "image" || !acceptable(declaredSize, MAX_BYTES)) return false
        return if (metered) declaredSize <= AUTO_MAX_BYTES else true
    }

    /**
     * Read [input] to the end, but never more than [cap] bytes: a stream that goes on past the
     * cap (a lying or missing Content-Length) is abandoned with [TooLarge] and nothing is kept.
     */
    /**
     * Copy [input] to [out], but never more than [cap] bytes: past the cap it stops with
     * [TooLarge] (the caller deletes what was written). Returns the bytes copied. Nothing is
     * held in memory beyond one buffer.
     */
    fun copyBounded(input: java.io.InputStream, out: java.io.OutputStream, cap: Long): Long {
        val buf = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            total += n
            if (total > cap) throw TooLarge(cap)
            out.write(buf, 0, n)
        }
        return total
    }

    fun readBounded(input: java.io.InputStream, cap: Long): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            total += n
            if (total > cap) throw TooLarge(cap)
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }
}

/**
 * How large one file may be on the skwod in front — the Android peer of the Apple app's
 * `UploadLimit`. The host chooses it (`SKWOD_MAX_UPLOAD_MB`, or the Mac app's host settings) and
 * the server reports it (`GET /api/instance/limits`). The app checks a file against it BEFORE
 * encrypting and shows the real number; the server refuses an oversized upload whatever the app
 * believes. Pure (no android.*) — unit-tested.
 */
object UploadLimit {
    const val MIB = 1024L * 1024
    /** A host that does not answer the question (older than build 45) allows the old fixed 100 MB. */
    const val DEFAULT_BYTES = AttachmentLimits.MAX_BYTES
    const val MIN_BYTES = 1 * MIB
    const val MAX_BYTES = 1900 * MIB
    /** A file encrypted in one piece in memory (a feed or story photo) is never larger than this. */
    const val IN_MEMORY_BYTES = 100 * MIB

    private val lock = Any()
    private val learned = HashMap<String, Long>()
    private var workspace = ""

    /** The limit of the skwod in front, as last learned (100 MB until it has been asked). */
    @Volatile var current: Long = DEFAULT_BYTES
        private set

    fun clamped(bytes: Long): Long = bytes.coerceIn(MIN_BYTES, MAX_BYTES)

    /** `max_upload_bytes` of the server's answer (its 413 carries it too), bounded; null when it is not there. */
    fun parse(body: String?): Long? = try {
        val v = if (body.isNullOrBlank()) null else org.json.JSONObject(body).opt("max_upload_bytes")
        val n = (v as? Number)?.toDouble()
        if (n == null || n.isNaN() || n < 1.0) null else clamped(minOf(n, MAX_BYTES.toDouble()).toLong())
    } catch (_: Exception) { null }

    /** A skwod came to the front: use what was last learned about it. */
    fun activate(workspaceId: String) = synchronized(lock) {
        if (workspace == workspaceId) return@synchronized
        workspace = workspaceId
        current = learned[workspaceId] ?: DEFAULT_BYTES
    }

    /** A skwod's local data was deleted: what was learned about it goes too. */
    fun forget(workspaceId: String) = synchronized(lock) {
        learned.remove(workspaceId)
        if (workspace == workspaceId) { workspace = ""; current = DEFAULT_BYTES }
    }

    /** The server answered ([bytes] null: it does not know the question — the old 100 MB). */
    fun learned(bytes: Long?, workspaceId: String) = synchronized(lock) {
        val value = bytes?.let { clamped(it) } ?: DEFAULT_BYTES
        learned[workspaceId] = value
        if (workspace == workspaceId || workspace.isEmpty()) { workspace = workspaceId; current = value }
    }

    /** May a file of [size] bytes be sent? [inMemory]: it will be encrypted in one piece. */
    fun allowsUpload(size: Long, limit: Long = current, inMemory: Boolean = false): Boolean =
        size >= 0 && size <= (if (inMemory) minOf(limit, IN_MEMORY_BYTES) else limit)

    /**
     * The most that is DOWNLOADED for one attachment. Never less than the old 100 MB: a host
     * that lowers its limit must not make files that are already there unopenable.
     */
    fun downloadCap(limit: Long = current): Long = maxOf(clamped(limit), DEFAULT_BYTES)

    /**
     * The most ciphertext that is ever read INTO MEMORY. A fixed bound: whatever limit a server
     * reports — a generous host or a hostile one — it never grows. Larger files only ever take
     * the streamed, file-to-file path.
     */
    fun inMemoryDownloadCap(limit: Long = current): Long = minOf(downloadCap(limit), IN_MEMORY_BYTES)

    /** "100 MB", "1.5 GB". */
    fun label(bytes: Long): String {
        val mb = bytes.toDouble() / MIB
        if (mb >= 1024) {
            val gb = mb / 1024
            return if (gb == Math.rint(gb)) "${gb.toLong()} GB" else String.format(java.util.Locale.US, "%.1f GB", gb)
        }
        return "${Math.round(mb)} MB"
    }

    fun tooLargeSentence(limit: Long = current): String =
        "That file is too large — this Skwod's host allows up to ${label(limit)} per file."

    /** Test hook: forget everything learned. */
    internal fun reset() = synchronized(lock) { learned.clear(); workspace = ""; current = DEFAULT_BYTES }
}

/**
 * Which part of a song's preview a story plays — the Android peer of the Apple app's `MusicClip`,
 * the same JSON (`"clip":{"startMs":…,"durationMs":…}` beside `music` in the encrypted story
 * payload). What it selects from is the song's ~30 second preview on Apple's hosts: the audio
 * every viewer can play, with no account. Both numbers are the SENDER's: construction brings
 * them inside the bounds, and [window] clamps again against the real audio at playback.
 */
class MusicClip private constructor(val startMs: Int, val durationMs: Int) {
    override fun equals(other: Any?): Boolean = other is MusicClip && other.startMs == startMs && other.durationMs == durationMs
    override fun hashCode(): Int = startMs * 31 + durationMs
    override fun toString(): String = "MusicClip($startMs, $durationMs)"

    fun toJson(): org.json.JSONObject = org.json.JSONObject().put("startMs", startMs).put("durationMs", durationMs)

    /** Where playback starts and ends (ms) in a preview that is really [previewMs] long (null = not known yet). */
    fun window(previewMs: Int?): Pair<Int, Int> {
        if (previewMs == null || previewMs <= 0) return startMs to startMs + durationMs
        val duration = minOf(durationMs, previewMs)
        val start = minOf(startMs, previewMs - duration)
        return start to start + duration
    }

    companion object {
        /** The lengths the composer offers (seconds). */
        val DURATION_CHOICES = listOf(5, 10, 15)
        const val DEFAULT_DURATION_MS = 15_000
        const val MIN_DURATION_MS = 1_000
        const val MAX_DURATION_MS = 30_000
        const val MAX_START_MS = 600_000
        const val ASSUMED_PREVIEW_MS = 30_000

        fun of(startMs: Int, durationMs: Int): MusicClip =
            MusicClip(startMs.coerceIn(0, MAX_START_MS), durationMs.coerceIn(MIN_DURATION_MS, MAX_DURATION_MS))

        /** A story with a song and no clip (builds before 45, or a clip that could not be read). */
        val FALLBACK = of(0, DEFAULT_DURATION_MS)

        /** What the composer makes: an offered length, kept inside a preview of [previewMs]. */
        fun chosen(startMs: Int, durationSeconds: Int, previewMs: Int = ASSUMED_PREVIEW_MS): MusicClip {
            val seconds = if (durationSeconds in DURATION_CHOICES) durationSeconds else DEFAULT_DURATION_MS / 1000
            val preview = maxOf(previewMs, MIN_DURATION_MS)
            val duration = minOf(seconds * 1000, preview)
            return of(startMs.coerceIn(0, preview - duration), duration)
        }

        /**
         * Lenient about the numbers (integer or decimal; clamped), strict about the shape: both
         * must be there and be numbers. Anything else is no clip — the story still shows.
         */
        fun fromJson(o: org.json.JSONObject?): MusicClip? {
            if (o == null) return null
            fun number(key: String): Int? {
                val n = (o.opt(key) as? Number)?.toDouble() ?: return null
                if (n.isNaN()) return null
                return n.coerceIn(-1.0, MAX_START_MS + 1.0).toInt()
            }
            return of(number("startMs") ?: return null, number("durationMs") ?: return null)
        }

        /** The `clip` of a decoded story payload, if it has a readable one. */
        fun inPayload(payload: org.json.JSONObject): MusicClip? = fromJson(payload.optJSONObject("clip"))

        /** "0:07". */
        fun clock(ms: Int): String { val s = maxOf(ms, 0) / 1000; return "${s / 60}:${(s % 60).toString().padStart(2, '0')}" }
    }
}

/** Where a post or story of mine stands on its way out — what the feed's progress shows. */
data class FeedSend(val stage: Stage, val uploaded: Float = 0f, val story: Boolean = false) {
    enum class Stage { ENCRYPTING, UPLOADING, SENDING }

    companion object {
        /**
         * The most that is shown for bytes still on their way. They have been handed to the
         * connection — on a p2p skwod, to the local proxy — not yet confirmed by the host.
         */
        const val IN_FLIGHT_CEILING = 0.97f
    }


    private val share: Float get() = uploaded.coerceIn(0f, 1f)
    /** One number for a progress ring: encrypting is the first sliver, the upload the rest. */
    val fraction: Float get() = when (stage) {
        Stage.ENCRYPTING -> 0.04f
        Stage.UPLOADING -> 0.04f + 0.92f * share
        Stage.SENDING -> 0.98f
    }
    val percent: Int get() = Math.round(share * 100)
    val label: String get() {
        val what = if (story) "story" else "post"
        return when (stage) {
            Stage.ENCRYPTING -> "Encrypting your $what…"
            // Everything has left this phone and the host has not confirmed the last piece yet.
            Stage.UPLOADING -> if (share >= IN_FLIGHT_CEILING && share < 1f) "Finishing the upload of your $what…" else "Uploading your $what… $percent%"
            Stage.SENDING -> "Posting your $what…"
        }
    }

    /** Progress only moves forward: chunks report from another thread and can arrive late. */
    fun advancedTo(share: Float): FeedSend =
        if (stage == Stage.UPLOADING && share <= uploaded) this else copy(stage = Stage.UPLOADING, uploaded = share.coerceIn(0f, 1f))
}

/**
 * How a story's song reaches the viewer — the Android peer of the Apple app's `StoryMusicPolicy`.
 *
 * The audio is Apple's preview of the song. A viewer's app NEVER fetches it from Apple: that
 * would show Apple the IP address of everyone who opens the story. It asks the viewer's own
 * Skwod host (`POST /api/music/preview`), which fetches it and hands the bytes back. The host
 * then knows this account played this preview, now; Apple sees only the host.
 *
 * By default that happens when the story opens. With "Play story music only when I tap" on,
 * NOTHING is fetched until the viewer taps the song — still via the host.
 */
object StoryMusicPolicy {
    /** The one host the server fetches previews from (`server/src/music.rs`): exact, never a suffix. */
    const val PREVIEW_HOST = "audio-ssl.itunes.apple.com"
    /** The server relays nothing larger; neither does this app accept more. */
    const val MAX_PREVIEW_BYTES = 4L * 1024 * 1024

    /** [url] if the host will fetch it — the same rules the server applies. */
    fun hostFetchable(url: String?): String? {
        if (url.isNullOrEmpty() || url.length > 600 || url.any { it.isWhitespace() || it.isISOControl() }) return null
        val uri = try { java.net.URI(url) } catch (_: Exception) { return null }
        if (uri.scheme?.lowercase() != "https" || uri.userInfo != null || uri.fragment != null) return null
        if (uri.host?.lowercase() != PREVIEW_HOST) return null
        if (uri.port != -1 && uri.port != 443) return null
        val path = uri.path ?: return null
        if (!path.startsWith("/itunes-assets/") || path.contains("..")) return null
        if (listOf(".m4a", ".mp3", ".aac").none { path.endsWith(it) }) return null
        return url
    }

    enum class OnOpen { FETCH, WAIT_FOR_TAP, SILENT }

    /** What happens to a story's song when the story opens ([tapped]: the viewer asked for it). */
    fun onOpen(tapToPlay: Boolean, tapped: Boolean, inCall: Boolean, hasPreview: Boolean): OnOpen = when {
        inCall || !hasPreview -> OnOpen.SILENT
        tapToPlay && !tapped -> OnOpen.WAIT_FOR_TAP
        else -> OnOpen.FETCH
    }
}
