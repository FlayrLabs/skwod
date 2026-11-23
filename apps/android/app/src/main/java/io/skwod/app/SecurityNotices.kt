package io.skwod.app

/** A security event to put in front of the user, with (optionally) something to do about it. */
data class SecurityAlert(val title: String, val message: String, val action: NoticeAction? = null)

sealed class NoticeAction {
    abstract val label: String

    /** Accept the devices the directory lists for a contact as theirs (clears "verified"). */
    /** [shown]: the contact's `acceptFingerprint` when the notice was raised (audit L2). */
    data class AcceptDevices(val userId: String, val shown: String = "") : NoticeAction() {
        override val label = "Accept"
    }

    /** Open the recovery-key flow: the account has no key in force any more. */
    data class RecoveryKey(val reason: RecoveryKeyReason) : NoticeAction() {
        override val label = if (reason == RecoveryKeyReason.DEVICE_REMOVED) "Make a new key" else "Save a recovery key"
    }
}

/**
 * Turns the core's security notices into what the user reads. One alert per notice: the app
 * queues all of them (a second notice must never be dropped because a first one is on screen).
 */
object SecurityNotices {
    const val BACKUP_FETCHED_TITLE = "Your key backup was downloaded"
    const val RECOVERY_MULTIPLE_TITLE = "More than one install is trying to restore your account"
    const val RECOVERY_MULTIPLE_MESSAGE = "Several restore requests are waiting for the same device, each with its own code. Approve only the one whose code matches the screen in front of you and block the rest. If none of them is you, block them all and change your password."
    const val BACKUP_FETCHED_MESSAGE = "Your key backup was downloaded by a sign-in that is not one of your devices. If this was not you, change your password and save a new recovery key."

    /** A skwod named by its id in a notice (the app has no trusted name for it here). */
    private fun serverName(serverId: String?): String = if (serverId.isNullOrEmpty()) "another skwod" else "skwod ${serverId.take(8)}…"

    /** A device shown by a short, recognisable prefix of its id. */
    fun device(id: String): String = if (id.isEmpty()) "a device" else "device ${id.take(8)}…"

    /**
     * [deviceLabel] names one of THIS account's devices (its name from `listDevices` when known,
     * else [device]); a contact's device is always shown by its short id.
     */
    fun alert(kind: String, userId: String, deviceId: String, wasVerified: Boolean, serverId: String?, nameOf: (String) -> String,
              fingerprint: String? = null, deviceLabel: (String) -> String = ::device): SecurityAlert? =
        when (kind) {
            "account_restored" -> SecurityAlert("Your account was restored on a new device",
                "${deviceLabel(deviceId).replaceFirstChar { it.uppercase() }} was restored from your recovery key, or came back after being erased. If that wasn't you, remove it in Devices and change your password.")
            "device_removed" -> SecurityAlert("A device was removed",
                "${deviceLabel(deviceId).replaceFirstChar { it.uppercase() }} was removed from your account and your recovery key was retired. Make a new recovery key.",
                NoticeAction.RecoveryKey(RecoveryKeyReason.DEVICE_REMOVED))
            "recovery_key_changed" -> SecurityAlert("Your recovery key changed",
                "The recovery key for your account was changed, removed or retired. If that wasn't you: restore with your old key within 7 days, or report it compromised in Profile → Encryption.")
            "recovery_key_needed" -> SecurityAlert("Save a new recovery key", "Your account has no recovery key now.",
                NoticeAction.RecoveryKey(RecoveryKeyReason.NEEDED))
            "owner_changed" -> SecurityAlert("A skwod's owner changed",
                "After your restore, a skwod reports a different owner than the one this account trusted. Its owner is unconfirmed until you check with them.")
            // Never an alert to tap away: it is a sheet with the code and Approve / Block. This
            // is how it reads in the Security activity list.
            "recovery_requested" -> SecurityAlert("A restore was requested", "Code ${fingerprint ?: ""}.")
            "protocol_upgraded" -> SecurityAlert("Encryption upgraded",
                "Skwod now uses the Signal protocol. This device has new encryption keys, so your contacts will see that your safety number changed — and theirs changed for you. Your message history on this device is kept. If you verified anyone before, verify them again.")
            "reset_blocked" -> SecurityAlert("Blocked an account reset",
                "Someone signed in to your account tried to reset its encryption and remove your devices. This device cancelled it. If that wasn't you, change your password now.")
            "unverified_device" -> SecurityAlert("Unrecognised device on your account",
                "The server lists ${device(deviceId)} on your account that none of your devices approved. Skwod is ignoring it: nothing is sent to it and nothing from it is trusted. If you did not try to add a device, change your password.")
            "device_linked" -> SecurityAlert("New device linked",
                "${device(deviceId).replaceFirstChar { it.uppercase() }} was linked to your account and can now read your new messages. If that wasn't you, remove it and change your password.")
            "new_device" -> SecurityAlert("${nameOf(userId)} added a device",
                "${nameOf(userId)} linked ${device(deviceId)}, vouched for by a device of theirs you already trust. Their messages may now come from it, and yours reach it too.")
            "unverified_contact_device" -> SecurityAlert("Unverified device for ${nameOf(userId)}",
                "The server lists ${device(deviceId)} for ${nameOf(userId)}, but none of their devices vouched for it. Skwod sends it nothing and is holding anything it sends." +
                    (if (wasVerified) " You had verified ${nameOf(userId)}: nothing at all is sent to them until you decide." else "") +
                    " Only accept it if ${nameOf(userId)} confirms — outside Skwod — that the device is theirs.",
                NoticeAction.AcceptDevices(userId))
            // Since build 45 this is ALSO "someone presented another key for this device and it
            // was refused" (sends not held, safety number unchanged) — the notice cannot tell the
            // two apart, so the wording fits both; the conversation's banner is decided by
            // `contactStatus` ([IdentityHold]).
            "identity_changed" -> SecurityAlert("A different key for ${nameOf(userId)}",
                "Someone presented a different security key for ${nameOf(userId)}'s ${device(deviceId)}. If they replaced or reinstalled a phone, your chat with them says what to do; otherwise Skwod refused the key and nothing changed. Compare safety numbers to be sure nobody is in the middle." +
                    (if (wasVerified) " You had verified ${nameOf(userId)}." else ""))
            // Raised by the app from the realtime `backup_fetched` event (the server's word only).
            "backup_fetched" -> SecurityAlert(BACKUP_FETCHED_TITLE, BACKUP_FETCHED_MESSAGE)
            // Raised by the app from the realtime `device_recovery_multiple` event (server L1).
            "recovery_multiple" -> SecurityAlert(RECOVERY_MULTIPLE_TITLE, RECOVERY_MULTIPLE_MESSAGE)
            // Raised by the core after a restore whose devices wait for confirmation (audit M2).
            "restored_devices_unconfirmed" -> SecurityAlert("Confirm your other devices",
                "This device was restored from a backup, which may be older than your account. Nothing is synced to the devices it lists until you confirm them: open Profile → Encryption → Devices and answer “Is this still your device?” for each one that is.")
            // `channel_opened` was refused: the channel is already confirmed in another skwod.
            "channel_remap_refused" -> SecurityAlert("A channel claimed to move to another skwod",
                "You opened a channel that this device already knows as part of ${serverName(serverId)}. The server now lists it under a different skwod. Skwod kept it where it was confirmed: a clear or deletion from the other skwod's owner does not apply to it.")
            "owner_change_refused" -> SecurityAlert("An invite claimed a different owner",
                "The invite you used names a different owner for a skwod this device already knows. Nothing was changed. If its owner really changed, leave it and join again from a fresh invite.")
            // "join_request" is not an alert: it shows in the members view ("Waiting to join").
            else -> null
        }

    /**
     * The JSON of a persistent system row (content STX + `skwod/sys|` + JSON) as the conversation
     * shows it, or null if it is not one this build knows. Same wording as the Apple app's
     * `SecurityAlert.systemMessage`.
     *
     * This only READS a row that is already known to be a system row. Whether a row is one is
     * decided by `Message.isSystem` — what the core recorded when it wrote the row — and never
     * by this text or by the author id: any member can send a body that starts with
     * `skwod/sys|`, and such a message is an ordinary message ([RowKind]).
     */
    fun systemRow(content: String, nameOf: (String) -> String): SystemRowInfo? {
        val i = content.indexOf("skwod/sys|")
        if (i < 0 || i > 1) return null
        val o = try { org.json.JSONObject(content.substring(i + "skwod/sys|".length)) } catch (_: Exception) { return null }
        val kind = o.optString("kind")
        val userId = o.optString("user_id")
        val user = nameOf(userId)
        val dev = device(o.optString("device_id"))
        val by = (if (o.isNull("by_user_id")) "" else o.optString("by_user_id")).takeIf { it.isNotEmpty() }?.let(nameOf)
        val wasVerified = o.optBoolean("was_verified")
        return when (kind) {
            "member_joined" -> SystemRowInfo(kind, userId,
                if (by != null) "$user joined (let in by ${if (by == "You") "you" else by})." else "$user joined.", SystemRowIcon.JOINED)
            "device_added", "new_device" -> SystemRowInfo(kind, userId,
                "$user added a device ($dev). It was vouched for by a device of theirs you already trust.", SystemRowIcon.DEVICE)
            "member_held" -> SystemRowInfo(kind, userId,
                "$user is waiting to join. The server lists them as a member, but nobody you trust has let them in, so this device has not given them any keys.",
                SystemRowIcon.HELD, warning = true, actionLabel = "Review")
            "unverified_contact_device" -> SystemRowInfo(kind, userId,
                "The server lists $dev for $user, but none of their devices vouched for it. Nothing is sent to it and what it sends is held.",
                SystemRowIcon.ALERT, warning = true, actionLabel = "View safety number")
            "identity_changed" -> SystemRowInfo(kind, userId,
                "Someone presented a different security key for $user's $dev." +
                    (if (wasVerified) " You had verified them — check the safety number." else ""),
                if (wasVerified) SystemRowIcon.ALERT else SystemRowIcon.SHIELD, warning = wasVerified, actionLabel = "View safety number")
            else -> null
        }
    }
}

enum class SystemRowIcon { JOINED, DEVICE, HELD, ALERT, SHIELD }

/**
 * "X is waiting to join" stays in history after it is settled (let in, declined or gone): then it
 * is a past event, not a warning with something to do. [stillWaiting] = the user is in the
 * "Waiting to join" list right now.
 */
fun SystemRowInfo.settledIfNotWaiting(stillWaiting: Boolean, nameOf: (String) -> String): SystemRowInfo =
    if (kind != "member_held" || stillWaiting) this
    else copy(
        text = "${nameOf(userId)} was listed by the server before anyone had let them in. They got no keys from this device while that was so.",
        warning = false, actionLabel = null,
    )

/** How a system row looks and what it offers (see [SecurityNotices.systemRow]). */
data class SystemRowInfo(
    /** The core's event kind: `member_joined`, `device_added`, `member_held`, `identity_changed`, … */
    val kind: String,
    /** Who the event is about. */
    val userId: String,
    val text: String,
    val icon: SystemRowIcon,
    /** Needs a decision (amber) rather than being a routine event. */
    val warning: Boolean = false,
    val actionLabel: String? = null,
)

/** The realtime `backup_fetched` event, de-duplicated by its time (pure). */
object BackupFetched {
    /** [last] = the newest `at` already shown; an event at or before it is a repeat. An event with no time is always shown. */
    fun alreadySaid(last: Long?, at: Long): Boolean = at > 0 && last != null && at <= last
}

/**
 * Whether a direct conversation shows the "messages are on hold" banner, and what it says (pure,
 * unit-tested). Decided from `contactStatus` and from what the outbox reports — never from a
 * notice alone: since build 45 an `identity_changed` notice may be a REFUSED impersonation,
 * after which nothing is held and the safety number is the one already shown.
 */
object IdentityHold {
    enum class Banner {
        NONE,
        /** Sends to the contact fail: their keys changed (verified contact), their only device is unvouched, or a send just failed for that reason. */
        HELD,
        /** Sends still reach the devices already trusted; a further device nobody vouched for gets nothing. */
        UNVOUCHED_DEVICE,
    }

    /** The core outbox's sentence for a send refused because the contact's keys changed (`IdentityChanged`). */
    fun isHeldFailure(reason: String): Boolean = reason.contains("safety number", ignoreCase = true)

    /**
     * [sendFailedHeld]: a queued send of this conversation failed with `IdentityChanged` (or a
     * direct send threw it) — a send that reached nobody.
     */
    fun banner(sendsHeld: Boolean, devices: Int, unvouchedDevices: Int, sendFailedHeld: Boolean): Banner = when {
        sendsHeld || sendFailedHeld -> Banner.HELD
        unvouchedDevices > 0 && devices == 0 -> Banner.HELD
        unvouchedDevices > 0 -> Banner.UNVOUCHED_DEVICE
        else -> Banner.NONE
    }

    fun title(banner: Banner, name: String): String = when (banner) {
        Banner.HELD -> "$name's security key changed. Messages to them are on hold until you accept or verify"
        Banner.UNVOUCHED_DEVICE -> "$name has a device none of their devices vouched for"
        Banner.NONE -> ""
    }

    fun body(banner: Banner, name: String, wasVerified: Boolean): String = when (banner) {
        Banner.HELD -> (if (wasVerified) "You verified $name, and since then their devices changed. " else "$name's devices changed — ") +
            "usually a new phone or a reinstall, but it is also what someone intercepting the conversation would look like. Messages you send are marked not delivered and wait until you decide. Verify compares safety numbers; Accept trusts the devices listed now (and $name is no longer verified)."
        Banner.UNVOUCHED_DEVICE -> "Your messages still reach the devices of theirs you already trust; the new one gets nothing and what it sends is held. Accept it only if $name confirms — outside Skwod — that the device is theirs."
        Banner.NONE -> ""
    }

    /** The queued sends to try again once the hold is lifted: every failed send of the conversation. */
    fun toRetry(states: Map<String, SendState>): List<String> = states.values.filterIsInstance<SendState.Failed>().map { it.localId }.distinct()
}
