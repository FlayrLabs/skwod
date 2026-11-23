package io.skwod.app

import org.json.JSONArray
import org.json.JSONObject

/**
 * Build 44a, the app's half: devices, recovery key, restore, sign-out, app lock.
 *
 * The rules live in the core (docs/FFI-CHANGES.md, "Build 44a"). What is here is routing — which
 * screen a state or a failure opens — and the words those screens use, kept pure (no android.*,
 * no FFI) so each decision is unit-tested on the JVM. Same structure as the Apple app's
 * `AccountSecurity.swift`.
 */

/** What this device calls itself until its owner renames it (sealed to the account's own devices). */
object DeviceLabel {
    const val MAX_LENGTH = 40

    /** The default name: the phone's model (`Build.MODEL`), or "Android" when it says nothing. */
    fun suggested(model: String?): String = cleaned(model ?: "").ifEmpty { "Android" }

    /** A name as the user typed it, made safe to store: trimmed, one line, bounded. */
    fun cleaned(raw: String): String = raw.replace('\n', ' ').replace('\r', ' ').trim().take(MAX_LENGTH).trim()

    /** How a device is listed: its name, or "Unnamed device". */
    fun shown(name: String?): String = name?.trim()?.takeIf { it.isNotEmpty() } ?: "Unnamed device"
}

/**
 * A restore of this account that is waiting for one of its devices to approve or block it.
 * [requestId] is the id from the notice that announced it — an answer is for THAT request.
 */
data class RecoveryRequest(val deviceId: String, val requestId: String, val fingerprint: String)

object RecoveryRequests {
    /**
     * The queue after a `recovery_requested` notice. Several installs may be asking to restore
     * the same device at once (server audit L1): each request has its own id and code and its
     * own prompt, side by side — none replaces another. A notice without a request id cannot be
     * answered and is not queued.
     */
    fun noted(queue: List<RecoveryRequest>, deviceId: String, requestId: String?, fingerprint: String?): List<RecoveryRequest> {
        if (requestId.isNullOrEmpty()) return queue
        val request = RecoveryRequest(deviceId, requestId, fingerprint ?: "")
        return if (queue.any { it.requestId == requestId }) queue else queue + request
    }

    /** The queue after [answered] was approved or blocked: approving one restore of a device ends every other request for it. */
    fun answered(queue: List<RecoveryRequest>, answered: RecoveryRequest, approved: Boolean): List<RecoveryRequest> =
        queue.filterNot { it.requestId == answered.requestId || (approved && it.deviceId == answered.deviceId) }

    /** The requests whose code starts with what was typed (dashes, spaces and case ignored). */
    fun matching(queue: List<RecoveryRequest>, code: String): List<RecoveryRequest> {
        val want = RecoveryKeyCheck.normalized(code)
        return if (want.isEmpty()) emptyList() else queue.filter { RecoveryKeyCheck.normalized(it.fingerprint).startsWith(want) }
    }

    const val REPLACED = "That request is no longer waiting — it was cancelled, or another restore was approved. Nothing was approved."
    const val APPROVED = "Approved. The new device will finish in a moment."
    const val BLOCKED = "Blocked. If that wasn't you, change your password."
}

/** Why the account PIN is being asked for, and what the last try said. */
data class PinPrompt(val purpose: Purpose, val attemptsLeft: Int? = null) {
    enum class Purpose {
        /** Resetting the account's devices (`resetDevices(pin)`). */
        RESET,
        /** Completing a restore that is waiting (`retryRestore(pin)`). */
        RESTORE,
    }

    /** The line under the field: nothing before the first try. */
    val message: String?
        get() = when {
            attemptsLeft == null -> null
            attemptsLeft <= 0 -> "Too many wrong PINs. Try again in 15 minutes."
            else -> "Wrong PIN. $attemptsLeft ${if (attemptsLeft == 1) "try" else "tries"} left."
        }

    /** No more tries for now: "Continue" is disabled. */
    val locked: Boolean get() = attemptsLeft != null && attemptsLeft <= 0
}

/** Why the recovery-key flow is on screen. Decides its header line and whether "Not now" is offered. */
enum class RecoveryKeyReason(val header: String?) {
    /** First run: this device is set up and the account has no recovery key. */
    FIRST_RUN(null),
    /** The user opened it from Profile. */
    MANUAL(null),
    /** A device was removed from the account, which retired the key. */
    DEVICE_REMOVED("Your old recovery key was retired with that device."),
    /** The user reported the key compromised. */
    COMPROMISED("Your old recovery key no longer works."),
    /** The core says no recovery key is in force (`recovery_key_needed`). */
    NEEDED("Your account has no recovery key now.");

    val offersNotNow: Boolean get() = this == FIRST_RUN
}

/** The recovery key as a person types part of it back. */
object RecoveryKeyCheck {
    /** ASCII letters and digits only, upper-cased: spaces, dashes and case never matter. */
    fun normalized(s: String): String =
        s.uppercase().filter { it in 'A'..'Z' || it in '0'..'9' }

    /** What the user is asked to type: the last 6 characters of the key. */
    fun tail(key: String): String = normalized(key).takeLast(6)

    fun matches(typed: String, key: String): Boolean {
        val want = tail(key)
        return want.length == 6 && normalized(typed) == want
    }
}

/** When the first-run recovery-key prompt may come up, and what the "saved" screen says. */
object RecoveryPrompt {
    const val SNOOZE_MS = 7L * 24 * 60 * 60 * 1000
    const val SNOOZE_KEY = "recovery.promptSnoozedUntil"

    /**
     * First run only: this install is an active device, the account has no recovery key, nothing
     * else about the account is on screen, and "Not now" was not chosen in the last 7 days.
     * (The `recovery_key_needed` notice prompts regardless of the snooze — it does not come here.)
     */
    fun due(active: Boolean, backupOn: Boolean, busyElsewhere: Boolean, snoozedUntilMs: Long, nowMs: Long): Boolean =
        active && !backupOn && !busyElsewhere && nowMs >= snoozedUntilMs

    fun snoozeUntil(nowMs: Long): Long = nowMs + SNOOZE_MS

    /** Step 3's body. [instantFrom] null or already past = the key restores at once. */
    fun savedBody(instantFrom: Long?, nowMs: Long, date: (Long) -> String): String =
        if (instantFrom == null || instantFrom <= nowMs) "Restoring with this key is instant."
        else "From ${date(instantFrom)}, restoring with this key is instant. Until then a restore also needs an approval from one of your devices, your account PIN, or a 7-day wait — so a key somebody just planted can't take your account."

    /** The Profile row's status while a key is in force. */
    fun rowStatus(instantFrom: Long?, nowMs: Long, date: (Long) -> String): String =
        if (instantFrom == null || instantFrom <= nowMs) "Instant restore ready" else "Instant from ${date(instantFrom)}"
}

/** "in 6 days 23 hours" — how long until a hold ends. */
object HoldCountdown {
    fun text(untilMs: Long, nowMs: Long): String {
        val seconds = (untilMs - nowMs) / 1000
        if (seconds <= 60) return "any moment now"
        val minutes = seconds / 60; val hours = minutes / 60; val days = hours / 24
        fun unit(n: Long, word: String) = "$n $word${if (n == 1L) "" else "s"}"
        if (days >= 1) {
            val rest = hours - days * 24
            return "in " + unit(days, "day") + (if (rest > 0) " " + unit(rest, "hour") else "")
        }
        if (hours >= 1) return "in " + unit(hours, "hour")
        return "in " + unit(minutes, "minute")
    }
}

/**
 * The line under the code on "Waiting to restore". A contested request (another install asked
 * to restore the same device) never completes by the hold, so it promises no countdown.
 * `null`: nothing to add yet (the server has not said when the hold ends).
 */
object RestoreWaitLine {
    const val CONTESTED = "Waiting for approval on one of your devices."

    fun text(completesAtMs: Long?, contested: Boolean, nowMs: Long): String? = when {
        contested -> CONTESTED
        completesAtMs == null -> null
        else -> "Or wait: it completes by itself ${HoldCountdown.text(completesAtMs, nowMs)}."
    }
}

/** Times as the account screens word them. */
object AccountDates {
    /** "Active now" under five minutes, else how long ago. */
    fun active(lastActiveMs: Long, nowMs: Long): String {
        if (lastActiveMs <= 0) return "Not active yet"
        if (nowMs - lastActiveMs < 5 * 60_000L) return "Active now"
        return "Active " + ago(lastActiveMs, nowMs)
    }

    /** "12 minutes ago", "3 hours ago", "2 days ago". */
    fun ago(atMs: Long, nowMs: Long): String {
        val minutes = ((nowMs - atMs) / 60_000L).coerceAtLeast(0)
        fun unit(n: Long, word: String) = "$n $word${if (n == 1L) "" else "s"} ago"
        return when {
            minutes < 1 -> "just now"
            minutes < 60 -> unit(minutes, "minute")
            minutes < 24 * 60 -> unit(minutes / 60, "hour")
            else -> unit(minutes / (24 * 60), "day")
        }
    }

    /** A calendar day in the device's own format ("Nov 19, 2026"). */
    fun day(ms: Long): String = java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM).format(java.util.Date(ms))
}

/**
 * Where this install stands with the account, and the screen that goes with it. The names are
 * the core's `DeviceState` values; a typed failure (`DeviceRemoved`, `DeviceSuperseded`,
 * `RecoveryPending`) never decides by itself — the state is re-read and routed from here.
 */
object InstallRoute {
    enum class Screen {
        /** A working device: the app. */
        APP,
        /** No device from this install: register, or (the account has devices) link / restore / reset. */
        SET_UP,
        /** "This device was removed". */
        REMOVED,
        /** "Your account was restored on another device". */
        SUPERSEDED,
        /** "Waiting to restore". */
        WAITING,
    }

    fun forState(state: String): Screen = when (state) {
        "ACTIVE" -> Screen.APP
        "REMOVED" -> Screen.REMOVED
        "SUPERSEDED" -> Screen.SUPERSEDED
        "RECOVERY_PENDING" -> Screen.WAITING
        else -> Screen.SET_UP
    }

    /** The typed failures after which the state is re-read (by the exception's simple name). */
    fun isDeviceError(kind: String?): Boolean = kind == "DeviceRemoved" || kind == "DeviceSuperseded" || kind == "RecoveryPending"

    /**
     * May this install register a device right now? Only with an opened cache, a reachable host
     * and no device yet. A cache that could not be opened must never lead to a registration: the
     * device made now would be forgotten at the next launch, and the account left with a ghost.
     */
    fun mayRegister(cacheOpened: Boolean, online: Boolean, screen: Screen): Boolean = cacheOpened && online && screen == Screen.SET_UP
}

/** What leaving does to what this device holds for a skwod. */
object LocalData {
    enum class Departure {
        /** "Sign out": the session token goes, nothing else. */
        SIGN_OUT,
        /** "Erase this device": the device left the account; its cache, key and record go too. */
        ERASE,
        /** The account itself was deleted on the server. */
        ACCOUNT_DELETED,
    }

    enum class Part { SESSION_TOKEN, CACHE_FILE, CACHE_KEY, WORKSPACE_RECORD }

    /**
     * Signing out keeps the cache, its key and the workspace record, so signing back in on this
     * device is the same device (`attachCache` → true, no link). Deleting any of them on
     * sign-out is the lock-out build 44 removes.
     */
    fun removedBy(departure: Departure): Set<Part> = when (departure) {
        Departure.SIGN_OUT -> setOf(Part.SESSION_TOKEN)
        Departure.ERASE, Departure.ACCOUNT_DELETED -> Part.entries.toSet()
    }

    // ---- what is kept under a skwod's id, outside its cache file and its record ----
    // The ONE list: these names are what the app reads and writes them by, and what a wipe
    // deletes them by — so an item kept per skwod cannot be missed when the skwod's data is
    // deleted (build 45 left the mutes behind after an erase).

    /** The cache key, in the encrypted store. */
    fun cacheKeyName(workspaceId: String) = "cache-key-$workspaceId"
    /** Which conversations of the skwod are muted and until when it is itself, in the encrypted store. */
    fun mutesName(workspaceId: String) = "mutes-$workspaceId"
    /** Until when the user had seen everything ([MessageNotifier]), in the notifier's preferences. */
    fun seenAtName(workspaceId: String) = "seenAt-$workspaceId"

    /** Which messages were announced ([MessageNotifier]'s ledger), in the encrypted store. */
    fun announcedName(workspaceId: String) = "announced-$workspaceId"
    /** The contact book ([ContactBook]), in the encrypted store. */
    fun contactsName(workspaceId: String) = "contacts-$workspaceId"
    /** The roster names the contact book was seeded from, in the encrypted store. */
    fun rosterName(workspaceId: String) = "roster-$workspaceId"

    /** Everything the ENCRYPTED store keeps under this skwod's id. */
    fun secretNames(workspaceId: String): List<String> =
        listOf(cacheKeyName(workspaceId), mutesName(workspaceId), announcedName(workspaceId), contactsName(workspaceId), rosterName(workspaceId))

    /**
     * Copies of an unreadable contact book are kept beside it as `contacts-<id>.unreadable.<ms>`
     * (nothing is deleted when it is read). They are this skwod's too: a wipe removes them by
     * prefix, from the names the store holds ([allNames]).
     */
    fun sideCopies(workspaceId: String, allNames: Collection<String>): List<String> =
        allNames.filter { it.startsWith("${contactsName(workspaceId)}.unreadable.") }
    /** Everything the notifier's preferences keep under it. */
    fun notifyNames(workspaceId: String): List<String> = listOf(seenAtName(workspaceId))

    /**
     * Delete all of it ([Part.CACHE_KEY]: erase, account deleted — never a sign-out).
     * [removeSecret] / [removeNotify] remove one name from the respective store.
     */
    fun forgetItems(workspaceId: String, removeSecret: (String) -> Unit, removeNotify: (String) -> Unit, secretNamesHeld: Collection<String> = emptyList()) {
        if (workspaceId.isEmpty()) return
        secretNames(workspaceId).forEach(removeSecret)
        sideCopies(workspaceId, secretNamesHeld).forEach(removeSecret)
        notifyNames(workspaceId).forEach(removeNotify)
    }

    /** The record of a skwod the user signed out of: everything but the session. */
    fun signedOut(w: Workspace): Workspace = w.copy(token = "", expiresAt = 0, tokenIssuedAt = 0, signedOutByUser = true)
}

/**
 * The per-workspace cache key as the secure store answered. "Could not be read" is NOT "there is
 * none": minting a new key over an unreadable one would orphan the encrypted cache (and with it
 * the device's identity) because of one transient Keystore failure.
 */
object CacheKeyPolicy {
    sealed interface Read {
        /** The store answered, and holds no key under this name. */
        data object Absent : Read
        data class Stored(val value: String) : Read
        /** The store threw (Keystore busy, the master key not available yet, I/O). */
        data object Unreadable : Read
    }

    sealed interface Decision {
        data class Use(val hex: String) : Decision
        /** No key yet (or a malformed one, which can decrypt nothing anyway): make one. */
        data object Mint : Decision
        /** Do nothing with this workspace's cache now; try again later. */
        data object Unavailable : Decision
    }

    fun decide(read: Read): Decision = when (read) {
        is Read.Unreadable -> Decision.Unavailable
        is Read.Absent -> Decision.Mint
        is Read.Stored -> if (wellFormed(read.value)) Decision.Use(read.value) else Decision.Mint
    }

    fun wellFormed(hex: String): Boolean = hex.length == 64 && hex.all { it in '0'..'9' || it in 'a'..'f' }
}

/** The app lock: when the app asks for the fingerprint / device passcode again. */
object AppLockPolicy {
    /** "Lock after": minutes → label. Default is 1 minute. */
    val options = listOf(0 to "Immediately", 1 to "1 minute", 5 to "5 minutes", 15 to "15 minutes", 60 to "1 hour")
    const val DEFAULT_MINUTES = 1

    fun label(minutes: Int): String = options.firstOrNull { it.first == minutes }?.second ?: "$minutes minutes"

    /** A stored value that is not one of the options falls back to the default. */
    fun normalized(minutes: Int): Int = if (options.any { it.first == minutes }) minutes else DEFAULT_MINUTES

    /** The app locks at launch always (when the lock is on). */
    fun lockedAtLaunch(enabled: Boolean): Boolean = enabled

    /**
     * Back from the background: lock when it was away for at least the chosen time. A clock that
     * went backwards counts as "long enough". Never while a call is up — the call would drop.
     */
    fun locksOnReturn(enabled: Boolean, backgroundedAtMs: Long?, nowMs: Long, afterMinutes: Int, callActive: Boolean): Boolean {
        if (!enabled || callActive || backgroundedAtMs == null) return false
        val away = nowMs - backgroundedAtMs
        return away < 0 || away >= afterMinutes * 60_000L
    }

    /** A prompt that has not answered for this long is treated as gone (its flag cannot wedge the lock). */
    const val PROMPT_TIMEOUT_MS = 60_000L

    /**
     * Everything the lock remembers. [promptStartedAt] / [promptIsUnlock] describe the system
     * prompt that is up: the UNLOCK prompt (shown while already locked), or some other one
     * (turning the lock on or off).
     */
    data class State(val locked: Boolean = false, val backgroundedAt: Long? = null, val promptStartedAt: Long? = null, val promptIsUnlock: Boolean = false) {
        /** A prompt is up — unless it has been "up" for longer than any prompt lasts. */
        fun prompting(nowMs: Long): Boolean = promptStartedAt != null && (nowMs - promptStartedAt) in 0 until PROMPT_TIMEOUT_MS
    }

    /** A prompt is about to be shown. It is the unlock prompt only if the app is locked right now. */
    fun promptStarted(s: State, forUnlock: Boolean, nowMs: Long): State = s.copy(promptStartedAt = nowMs, promptIsUnlock = forUnlock && s.locked)

    /**
     * The prompt answered. A successful UNLOCK opens the app and starts a fresh foreground.
     * A failure or a cancel changes nothing but the prompt itself: above all it never forgets
     * that the app went to the background — forgetting that is how a cancel followed by a
     * trip to the background used to leave the app open.
     */
    fun promptFinished(s: State, success: Boolean): State =
        if (success && s.promptIsUnlock) s.copy(locked = false, backgroundedAt = null, promptStartedAt = null, promptIsUnlock = false)
        else s.copy(promptStartedAt = null, promptIsUnlock = false)

    /**
     * The app left the foreground. The moment is recorded — except while the unlock prompt of
     * an already-locked app is up (the prompt itself can take the app out of the foreground,
     * and the app is locked anyway). Any other prompt records it as usual. The earliest moment
     * is kept: a second trip away never makes the absence look shorter.
     */
    fun backgrounded(s: State, nowMs: Long): State =
        if (s.locked && s.promptIsUnlock && s.prompting(nowMs)) s
        else s.copy(backgroundedAt = s.backgroundedAt?.let { minOf(it, nowMs) } ?: nowMs)

    /** The app is in front again: lock if it was away long enough, and start a fresh foreground. */
    fun foregrounded(s: State, enabled: Boolean, afterMinutes: Int, callActive: Boolean, nowMs: Long): State {
        val lock = locksOnReturn(enabled, s.backgroundedAt, nowMs, afterMinutes, callActive)
        // Kept through a call (nothing locks mid-call; the absence still counts afterwards).
        return s.copy(locked = s.locked || lock, backgroundedAt = if (callActive && enabled && !s.locked) s.backgroundedAt else null)
    }

    /** May a new prompt be shown? Not over one that is up — but a stuck flag times out. */
    fun mayPrompt(s: State, nowMs: Long): Boolean = !s.prompting(nowMs)
}

/** "Block screenshots and screen recording": on for NEW installs only. */
object ScreenSecurityDefault {
    /**
     * [stored] is the saved preference (null = never set). An install with a preference keeps
     * it. One with no preference is new when it has no workspace yet (→ on); an existing
     * install that never touched the switch keeps what it had (off).
     */
    fun value(stored: Boolean?, hasWorkspace: Boolean): Boolean = stored ?: !hasWorkspace
}

/** One row of Profile → Encryption → Security activity. */
data class SecurityEvent(val kind: String, val title: String, val message: String, val atMs: Long)

/** The persistent "Security activity" list (kv key `security.activity`, newest first, max 100). */
object SecurityActivity {
    const val KEY = "security.activity"
    const val MAX = 100

    /** [list] with [event] added — once: the same notice read twice is one row. */
    fun added(list: List<SecurityEvent>, event: SecurityEvent): List<SecurityEvent> {
        if (list.any { it.kind == event.kind && it.atMs == event.atMs && it.title == event.title }) return list
        return (list + event).sortedByDescending { it.atMs }.take(MAX)
    }

    fun encode(list: List<SecurityEvent>): String = JSONArray().apply {
        for (e in list) put(JSONObject().put("kind", e.kind).put("title", e.title).put("message", e.message).put("at_ms", e.atMs))
    }.toString()

    /**
     * STRICT: null unless the whole value is a list of rows. The log is then kept aside and
     * salvaged ([decode]) rather than silently emptied and written back.
     */
    fun decodeStrict(json: String?): List<SecurityEvent>? {
        if (json.isNullOrBlank()) return emptyList()
        val arr = try { JSONArray(json) } catch (_: Exception) { return null }
        for (i in 0 until arr.length()) if (arr.optJSONObject(i)?.optString("title").isNullOrEmpty()) return null
        return decode(json)
    }

    /** Tolerant (what can be salvaged): anything unreadable is an empty list, and a malformed row is skipped. */
    fun decode(json: String?): List<SecurityEvent> = try {
        if (json.isNullOrBlank()) emptyList() else {
            val arr = JSONArray(json)
            (0 until arr.length()).mapNotNull { i ->
                val o = arr.optJSONObject(i) ?: return@mapNotNull null
                // `atMs` is what the Apple app's encoder writes for the same list.
                val at = if (o.has("at_ms")) o.optLong("at_ms") else o.optLong("atMs")
                val title = o.optString("title")
                if (title.isEmpty()) null else SecurityEvent(o.optString("kind"), title, o.optString("message"), at)
            }.sortedByDescending { it.atMs }.take(MAX)
        }
    } catch (_: Exception) { emptyList() }
}

/** The words of the erase sheet that depend on what `eraseCheck()` said. */
object EraseCopy {
    const val TITLE = "Erase this device"
    const val BODY = "Removes this device from your account and deletes its messages and keys from this phone. Your account and your other devices are not touched."
    const val UNSAFE = "You need a recovery key or another device first. Without one, erasing leaves only a 7-day account reset — and nothing can bring your message history back."
    const val LOST_TOGGLE = "This device is lost, stolen or being given away"
    const val LOST_CAPTION = "Erases it as lost: it can never be restored, and your recovery key is retired at once. You'll make a new one on another device."

    /** The erase button is hidden behind the warning until the user says "Erase anyway". */
    fun eraseOffered(safe: Boolean, confirmedUnsafe: Boolean): Boolean = safe || confirmedUnsafe

    /** A failure that means the server was not reached: "Erase anyway (offline)" is offered. */
    fun offersOffline(errorKind: String?): Boolean = errorKind == "Network" || errorKind == "Engine"
}

/** The Devices screen's ordering and words. */
object DeviceRows {
    data class Row(val deviceId: String, val name: String?, val createdAt: Long, val lastActiveAt: Long, val isThisDevice: Boolean, val verified: Boolean)

    /** This device first, then by when each was added. */
    fun sorted(rows: List<Row>): List<Row> = rows.sortedWith(compareByDescending<Row> { it.isThisDevice }.thenBy { it.createdAt })

    fun count(n: Int, max: Int): String = "$n of $max"
    fun countLine(n: Int, max: Int): String = "$n of $max devices"
    fun atLimit(n: Int, max: Int): Boolean = max > 0 && n >= max
    fun limitLine(max: Int): String = "You've reached the $max-device limit. Remove one to link another."

    /** "Added ‹date› · Active ‹relative time›". */
    fun secondLine(row: Row, nowMs: Long, date: (Long) -> String = AccountDates::day): String =
        "Added ${date(row.createdAt)} · ${AccountDates.active(row.lastActiveAt, nowMs)}"

    const val UNVERIFIED = "Not approved by any of your devices"

    /** This device can be renamed; any other can be removed. */
    fun action(row: Row): String = if (row.isThisDevice) "Rename" else "Remove"

    /** The device whose name or id prefix was given (the DEBUG hooks' `removedevice:`). */
    fun find(rows: List<Row>, nameOrIdPrefix: String): Row? {
        val want = nameOrIdPrefix.trim()
        if (want.isEmpty()) return null
        return rows.firstOrNull { it.name.equals(want, ignoreCase = true) } ?: rows.singleOrNull { it.deviceId.startsWith(want, ignoreCase = true) }
    }
}
