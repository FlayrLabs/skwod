package io.skwod.app

import kotlinx.coroutines.sync.withLock
import uniffi.skwod_core.SkwodClient
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import uniffi.skwod_core.CoreException
import uniffi.skwod_core.DeviceList

/**
 * Which typed failure the core threw, by name — spelled out rather than read from the class, so
 * it does not depend on what the release build's shrinker leaves of the class names.
 */
fun coreErrorKind(e: Throwable): String? = when (e) {
    is CoreException.DeviceRemoved -> "DeviceRemoved"
    is CoreException.DeviceSuperseded -> "DeviceSuperseded"
    is CoreException.RecoveryPending -> "RecoveryPending"
    is CoreException.RecoveryChanged -> "RecoveryChanged"
    is CoreException.PinRequired -> "PinRequired"
    is CoreException.PinIncorrect -> "PinIncorrect"
    is CoreException.DeviceLimit -> "DeviceLimit"
    is CoreException.ResetPending -> "ResetPending"
    is CoreException.LinkRequired -> "LinkRequired"
    is CoreException.UpdateRequired -> "UpdateRequired"
    is CoreException.IdentityChanged -> "IdentityChanged"
    is CoreException.Invalid -> "Invalid"
    is CoreException.Engine -> "Engine"
    is CoreException.Cache -> "Cache"
    is CoreException.NoCache -> "NoCache"
    else -> null
}

/** The sentence a typed failure carries for the user, if it has one. */
fun coreErrorDetail(e: Throwable): String? = when (e) {
    is CoreException.DeviceRemoved -> e.detail
    is CoreException.DeviceSuperseded -> e.detail
    is CoreException.RecoveryPending -> e.detail
    is CoreException.RecoveryChanged -> e.detail
    is CoreException.PinRequired -> e.detail
    is CoreException.PinIncorrect -> e.detail
    is CoreException.DeviceLimit -> e.detail
    is CoreException.ResetPending -> e.detail
    is CoreException.LinkRequired -> e.detail
    is CoreException.IdentityChanged -> e.detail
    is CoreException.Invalid -> e.detail
    is CoreException.Engine -> e.detail
    is CoreException.Cache -> e.detail
    else -> null
}?.takeIf { it.isNotBlank() }

/**
 * Devices, the recovery key, restores and the security activity list of the active workspace —
 * the Android peer of the Apple app's `AccountSecurity.swift` extension. The rules are the
 * core's; this holds what the account screens share and makes the calls in the right order.
 */
class AccountFlows(private val model: AppModel) {
    /** Restores of this account waiting for THIS device to approve or block them, oldest first. */
    val recoveryRequests = mutableStateListOf<RecoveryRequest>()
    /** What happened to the restore request the user just answered. */
    var recoveryOutcome by mutableStateOf<String?>(null)
    /** Why the recovery-key flow is up (null = not shown). */
    var recoveryKeyPrompt by mutableStateOf<RecoveryKeyReason?>(null)
    /** The account PIN is being asked for (a reset, or a waiting restore). */
    var pinPrompt by mutableStateOf<PinPrompt?>(null)
    /** Profile → Encryption → Security activity, newest first. */
    var activity by mutableStateOf<List<SecurityEvent>>(emptyList())
        private set
    /** One line after a restore finished ("Your account is back."). */
    var restoredLine by mutableStateOf<String?>(null)
    /** Bumped when this account's devices or recovery key changed: open account screens reload. */
    val revision = mutableIntStateOf(0)
    /** Requests the user chose to "Decide later": kept in Profile → Encryption until answered or replaced. */
    val deferred = mutableStateListOf<RecoveryRequest>()
    /** The user closed the "Waiting to restore" screen; Profile → Encryption reopens it. */
    var waitingClosed by mutableStateOf(false)
    /** The reset that is waiting was started with "Forgot PIN?" (its retry is the same call). */
    @Volatile var resetIsForgotPin = false

    @Volatile private var deviceNames: Map<String, String> = emptyMap()

    fun reset() {
        recoveryRequests.clear(); deferred.clear(); waitingClosed = false
        recoveryOutcome = null; recoveryKeyPrompt = null; pinPrompt = null
        activity = emptyList(); restoredLine = null; deviceNames = emptyMap(); resetIsForgotPin = false
        keyBackupJob?.cancel(); keyBackupJob = null
    }

    // ---- security activity (persistent rows) ----

    /** The workspace whose events [activity] is showing, and the one whose STORED log it was built on (null: not read). */
    @Volatile private var activityShownFor: String? = null
    @Volatile private var activityReadFor: String? = null
    /** Events logged while the stored log could not be read or written, per workspace. */
    private val activityWaiting = ArrayList<Pair<String, SecurityEvent>>()
    private val activityLock = kotlinx.coroutines.sync.Mutex()

    /** What is on screen is [wid]'s: another workspace's events never stay under it. Call under [activityLock]. */
    private fun showActivity(wid: String) {
        if (activityShownFor == wid) return
        activityShownFor = wid; activityReadFor = null
        activity = activityWaiting.filter { it.first == wid }.map { it.second }.sortedByDescending { it.atMs }
    }

    /**
     * Read the stored list — STRICTLY (`kv_read`). The log is the record of what happened to
     * this account's security; it is never replaced by an empty one because it could not be read:
     * - the read fails: what is on screen stays, the log is NOT marked read, and nothing is
     *   written until a later read succeeds (events logged meanwhile wait in memory);
     * - it is read but cannot be decoded: its bytes are first kept under a key of their own
     *   (read back), then the log continues with what could be salvaged and says so. If the
     *   copy cannot be written, it stays unread.
     */
    suspend fun loadActivity() {
        var keptAs: String? = null
        val asked = model.bound
        activityLock.withLock {
            if (asked == null) { activity = emptyList(); activityShownFor = null; activityReadFor = null; return }
            showActivity(asked.workspaceId)
            val stored = try { asked.client.kvRead(SecurityActivity.KEY) } catch (_: Exception) { return }
            var events = SecurityActivity.decodeStrict(stored)
            if (events == null) {
                val side = "${SecurityActivity.KEY}.unreadable.${System.currentTimeMillis()}"
                try { asked.client.kvWrite(side, stored!!); if (asked.client.kvRead(side) != stored) return } catch (_: Exception) { return }
                events = SecurityActivity.decode(stored); keptAs = side
            }
            if (model.bound !== asked) return
            // Events logged while the log could not be read belong to this workspace's log too.
            val waiting = activityWaiting.filter { it.first == asked.workspaceId }.map { it.second }
            var all: List<SecurityEvent> = events
            for (e in waiting) all = SecurityActivity.added(all, e)
            activity = all; activityReadFor = asked.workspaceId
            if (waiting.isNotEmpty() && keptAs == null) writeActivity(asked)
        }
        keptAs?.let { log("security_activity_unreadable", "Security activity could not be read",
            "The record of security events Skwod keeps on this phone could not be fully read. Skwod kept what it could read and continues with that. Nothing was deleted: the data as it was is kept on this phone (as “$it”).",
            System.currentTimeMillis()) }
    }

    /** Write the log as it is now. Call under [activityLock]. */
    private suspend fun writeActivity(asked: BoundClient<SkwodClient>): Boolean {
        if (activityReadFor != asked.workspaceId) return false
        try { asked.client.kvWrite(SecurityActivity.KEY, SecurityActivity.encode(activity)) } catch (_: Exception) { return false }
        activityWaiting.removeAll { it.first == asked.workspaceId }
        return true
    }

    /**
     * Append one event (newest first, at most 100 kept) to the list in the encrypted cache.
     * Returns whether the event's row is STORED. While the log has not been read (or the write
     * fails) the event is shown and waits in memory; it is written with the next successful
     * read or write — the stored log is never overwritten by a list that was not built on it.
     * [workspaceId]: the workspace the event is about; it is not logged in another one's.
     */
    suspend fun log(kind: String, title: String, message: String, atMs: Long, workspaceId: String? = null): Boolean = activityLock.withLock {
        val asked = model.bound ?: return@withLock false
        if (workspaceId != null && workspaceId != asked.workspaceId) return@withLock false
        showActivity(asked.workspaceId)
        val event = SecurityEvent(kind, title, message, atMs)
        val next = SecurityActivity.added(activity, event)
        if (next === activity) return@withLock activityReadFor == asked.workspaceId && activityWaiting.none { it.second == event }
        activity = next
        if (activityReadFor == asked.workspaceId && writeActivity(asked)) return@withLock true
        activityWaiting += asked.workspaceId to event
        false
    }

    // ---- devices ----

    /** A device of this account as a notice names it: its name when known, else a short id. */
    fun deviceLabel(deviceId: String): String = deviceNames[deviceId] ?: SecurityNotices.device(deviceId)

    /** Re-read this account's devices (names for notices; the Devices screen reads the same). */
    suspend fun refreshDeviceNames(): DeviceList? {
        val c = model.client ?: return null
        val list = try { c.listDevices() } catch (e: Exception) { model.routeIfDeviceError(e); return null }
        deviceNames = list.devices.mapNotNull { d -> d.name?.takeIf { it.isNotEmpty() }?.let { d.deviceId to it } }.toMap()
        return list
    }

    /**
     * Something about this account's devices or recovery changed (a realtime nudge, or the user
     * just did it): re-read the device list from the server, then show what the core concluded.
     * The events carry nothing to act on by themselves.
     */
    suspend fun accountChanged() {
        val c = model.client ?: return
        if (model.baseUrl == null) return
        try { c.refreshOwnDevices() } catch (e: Exception) { if (model.routeIfDeviceError(e)) { revision.intValue++; return } }
        refreshDeviceNames()
        model.surfaceSecurityNotices()
        model.routeDeviceState()
        revision.intValue++
    }

    /**
     * A contact removed one of their devices: re-read theirs, so a later restore of that device
     * is told apart from one that erased itself (FFI-CHANGES, "Why a device left").
     */
    suspend fun contactDeviceRemoved(userId: String) {
        val c = model.client ?: return
        if (userId.isEmpty()) return
        try { c.refreshDevicesOf(userId) } catch (_: Exception) {}
        model.surfaceSecurityNotices()
    }

    // ---- recovery requests (approve / block on this device) ----

    fun noteRecoveryRequest(deviceId: String, requestId: String?, fingerprint: String?, atMs: Long) {
        if (requestId.isNullOrEmpty()) return
        // A request that replaced one the user had put off replaces it there too — and prompts,
        // because it is a new request with a new code.
        deferred.removeAll { it.deviceId == deviceId && it.requestId != requestId }
        if (deferred.any { it.requestId == requestId }) return
        val next = RecoveryRequests.noted(recoveryRequests.toList(), deviceId, requestId, fingerprint)
        if (next != recoveryRequests.toList()) { recoveryRequests.clear(); recoveryRequests.addAll(next) }
        model.launchIO { log("recovery_requested", "A restore was requested", "Code ${fingerprint ?: ""}.", atMs) }
        if (!model.appForeground) model.notifier.account("recovery-$requestId", "Restore your account?",
            "A new device is asking to restore your account. Open Skwod to approve or block it.")
    }

    enum class RecoveryAnswer { APPROVED, BLOCKED, CHANGED, FAILED }

    /**
     * Approve or block the request ON SCREEN — by its id, so an answer can never land on a
     * request that replaced it. CHANGED: it was replaced; nothing was approved, and the newer
     * request arrives as a fresh notice with its own code and gets its own prompt.
     */
    suspend fun answer(request: RecoveryRequest, approve: Boolean): Pair<RecoveryAnswer, String> {
        val c = model.client ?: return RecoveryAnswer.FAILED to "Not connected."
        return try {
            if (approve) c.approveRecovery(request.deviceId, request.requestId) else c.cancelRecovery(request.deviceId, request.requestId)
            val left = RecoveryRequests.answered(recoveryRequests.toList(), request, approve)
            recoveryRequests.clear(); recoveryRequests.addAll(left)
            deferred.removeAll { it.requestId == request.requestId }
            log(if (approve) "recovery_approved" else "recovery_blocked",
                if (approve) "You approved a restore" else "You blocked a restore", "Code ${request.fingerprint}.", System.currentTimeMillis())
            // Approving a restore of THIS device stops this install once it completes.
            accountChanged()
            if (approve) RecoveryAnswer.APPROVED to RecoveryRequests.APPROVED else RecoveryAnswer.BLOCKED to RecoveryRequests.BLOCKED
        } catch (_: CoreException.RecoveryChanged) {
            recoveryRequests.removeAll { it.requestId == request.requestId }
            deferred.removeAll { it.requestId == request.requestId }
            // The newer request is already listed by the server: pick it up now.
            accountChanged()
            RecoveryAnswer.CHANGED to RecoveryRequests.REPLACED
        } catch (e: Exception) {
            if (model.routeIfDeviceError(e)) RecoveryAnswer.FAILED to "This device can no longer answer for your account."
            else RecoveryAnswer.FAILED to (coreErrorDetail(e) ?: "Couldn't reach your Skwod — try again.")
        }
    }

    // ---- recovery key ----

    /**
     * First-run prompt: this device is set up, the account has no recovery key, and the user has
     * not said "Not now" in the last 7 days ([RecoveryPrompt.due]).
     */
    suspend fun maybePromptForRecoveryKey() {
        val c = model.client ?: return
        if (model.baseUrl == null || recoveryKeyPrompt != null || E2E.suppressRecoveryPrompt()) return
        val backupOn = try { c.keyBackupEnabled() } catch (_: Exception) { return }
        val until = try { c.kvGet(RecoveryPrompt.SNOOZE_KEY)?.toLongOrNull() ?: 0L } catch (_: Exception) { 0L }
        val busy = model.stopped != null || model.recoveryWaiting || model.needsDeviceLink || model.resetPending != null
        if (RecoveryPrompt.due(model.deviceId != null, backupOn, busy, until, System.currentTimeMillis())) recoveryKeyPrompt = RecoveryKeyReason.FIRST_RUN
    }

    /** "Not now": ask again in 7 days. */
    suspend fun snoozeRecoveryKeyPrompt() {
        try { model.client?.kvSet(RecoveryPrompt.SNOOZE_KEY, RecoveryPrompt.snoozeUntil(System.currentTimeMillis()).toString()) } catch (_: Exception) {}
    }

    private var keyBackupJob: Job? = null

    /**
     * The space list changed: bring the key backup up to date (the core does nothing when backup
     * is off). Debounced — joining a server adds several channels in a row. The Apple app does
     * the same (`ChatModel.touchKeyBackup`); without it a restore brings back an older set of
     * servers than the account is in.
     */
    fun touchKeyBackup() {
        val c = model.client ?: return
        keyBackupJob?.cancel()
        keyBackupJob = model.launchJob {
            delay(3000)
            if (model.client === c && model.deviceId != null && model.baseUrl != null) try { c.updateKeyBackup() } catch (_: Exception) {}
        }
    }

    // ---- restore, reset ----

    sealed interface RestoreOutcome {
        data object Restored : RestoreOutcome
        /** A recovery request: another device's approval, the PIN, or the 7-day hold. */
        data object Waiting : RestoreOutcome
        /** The PIN screen is up. */
        data object Pin : RestoreOutcome
        data object NoBackup : RestoreOutcome
        data object WrongKey : RestoreOutcome
        data class Failed(val why: String) : RestoreOutcome
    }

    /** One restore attempt and where it leads — shared by the dialog and the DEBUG hook. */
    suspend fun restore(key: String): RestoreOutcome {
        val c = model.client ?: return RestoreOutcome.Failed("Not connected.")
        return try {
            if (!c.restoreKeyBackup(key.trim())) RestoreOutcome.NoBackup else finishedRestore()
        } catch (e: Exception) { routeRestoreError(e) }
    }

    /** Complete a waiting restore ([pin] when the user has one). */
    suspend fun retryRestore(pin: String?): RestoreOutcome {
        val c = model.client ?: return RestoreOutcome.Failed("Not connected.")
        return try {
            if (!c.retryRestore(pin?.takeIf { it.isNotEmpty() })) RestoreOutcome.Waiting else finishedRestore()
        } catch (e: Exception) { routeRestoreError(e) }
    }

    private suspend fun finishedRestore(): RestoreOutcome {
        pinPrompt = null
        model.deviceBecameActive()
        restoredLine = "Your account is back."
        return RestoreOutcome.Restored
    }

    private suspend fun routeRestoreError(e: Exception): RestoreOutcome =
        when (RestoreErrors.classify(coreErrorKind(e), coreErrorDetail(e))) {
            RestoreErrors.Kind.WAITING -> { model.routeDeviceState(); RestoreOutcome.Waiting }
            RestoreErrors.Kind.PIN -> {
                pinPrompt = PinPrompt(PinPrompt.Purpose.RESTORE, (e as? CoreException.PinIncorrect)?.attemptsLeft?.toInt())
                RestoreOutcome.Pin
            }
            RestoreErrors.Kind.WRONG_KEY -> RestoreOutcome.WrongKey
            RestoreErrors.Kind.STOPPED -> { model.routeDeviceState(); RestoreOutcome.Failed("This device can no longer do that for your account.") }
            RestoreErrors.Kind.FAILED -> RestoreOutcome.Failed(coreErrorDetail(e) ?: "Couldn't reach your Skwod — try again.")
        }

    /**
     * Reset this account's encryption onto this device. With a PIN on the account the core asks
     * for it (`PinRequired` → the PIN screen); a wrong one says how many tries are left. Without
     * a (seasoned) PIN the reset waits 7 days. Returns a sentence only when it simply failed.
     */
    suspend fun resetDevices(pin: String?): String? {
        val c = model.client ?: return "Not connected."
        return try {
            c.resetDevices(pin?.takeIf { it.isNotEmpty() })
            resetIsForgotPin = false; pinPrompt = null
            model.deviceBecameActive()
            null
        } catch (e: CoreException.ResetPending) {
            // No PIN (or too young a PIN): the reset now waits 7 days, and any device still on
            // the account cancels it. Explain that, don't hide it.
            pinPrompt = null; resetIsForgotPin = false
            model.resetPending = e.detail
            null
        } catch (_: CoreException.PinRequired) {
            pinPrompt = PinPrompt(PinPrompt.Purpose.RESET); null
        } catch (e: CoreException.PinIncorrect) {
            pinPrompt = PinPrompt(PinPrompt.Purpose.RESET, e.attemptsLeft.toInt()); null
        } catch (e: Exception) {
            if (model.routeIfDeviceError(e)) null else coreErrorDetail(e) ?: "Something went wrong — check your connection."
        }
    }

    /** "Forgot PIN?": there is no shortcut — the same cancellable 7-day hold as an account without a PIN. */
    suspend fun resetForgotPin(): String? {
        val c = model.client ?: return "Not connected."
        return try {
            c.resetDevicesForgotPin()
            pinPrompt = null; resetIsForgotPin = false
            model.resetPending = null
            model.deviceBecameActive()
            null
        } catch (e: CoreException.ResetPending) {
            pinPrompt = null; resetIsForgotPin = true
            model.resetPending = e.detail
            null
        } catch (e: Exception) { coreErrorDetail(e) ?: "Couldn't start the reset — check your connection." }
    }

    /**
     * The stopped install is being set up again as a NEW device of the account: forget the old
     * registration (space keys, pins and contacts are kept) and offer link / restore / reset.
     */
    suspend fun setUpAgain() {
        val c = model.client ?: return
        val superseded = try { c.deviceState().name == "SUPERSEDED" } catch (_: Exception) { false }
        try { c.forgetRegistration() } catch (_: Exception) { return }
        // The session is the superseded install's: the server refuses it everything but binding
        // (not the key backup a restore needs). End it here — keys and cache stay — and log in
        // again; the new session sets this install up as a new device.
        if (superseded) { model.endSupersededSession(); return }
        model.routeDeviceState(registerIfNew = true)
        if (model.deviceId != null) model.deviceBecameActive()
    }
}

/** What a failed restore means for the screens (pure). */
object RestoreErrors {
    enum class Kind { WAITING, PIN, WRONG_KEY, STOPPED, FAILED }

    fun classify(kind: String?, detail: String?): Kind = when (kind) {
        "RecoveryPending" -> Kind.WAITING
        "PinRequired", "PinIncorrect" -> Kind.PIN
        "DeviceRemoved", "DeviceSuperseded" -> Kind.STOPPED
        // The backup would not open under what was typed.
        "Invalid" -> if (detail != null && (detail.contains("wrong passphrase") || detail.contains("backup decrypt failed"))) Kind.WRONG_KEY else Kind.FAILED
        else -> Kind.FAILED
    }
}

/** What a realtime event asks the account layer to do (pure). */
object AccountEvents {
    sealed interface Action {
        data object None : Action
        /** About this account: `refreshOwnDevices()`, then surface the notices. */
        data object OwnAccount : Action
        /** A contact removed a device, or one of theirs was restored onto another install (`device_rekeyed`): `refreshDevicesOf(userId)`. */
        data class PeerDeviceRemoved(val userId: String) : Action
    }

    private val own = setOf("device_added", "device_removed", "link_request", "device_recovery_requested", "device_rekeyed",
        "account_restored", "recovery_key_changed", "backup_updated", "sessions_revoked", "device_recovery_multiple")

    /**
     * [onOwnTopic] = the event came on `user:<me>`. `device_removed` names whose device it was:
     * someone else's is theirs to re-read, wherever it arrived (`server:<id>` or `user:<me>`).
     * Everything else counts only on our own topic — a server topic cannot nudge the account.
     */
    fun action(event: String, onOwnTopic: Boolean, payloadUserId: String, me: String): Action {
        // `device_rekeyed` (build 45) is read the same way: someone else's device is at a new
        // generation, so what it held rotates — the core needs their device list re-read.
        val perDevice = event == "device_removed" || event == "device_rekeyed"
        if (perDevice && payloadUserId.isNotEmpty() && payloadUserId != me) return Action.PeerDeviceRemoved(payloadUserId)
        if (perDevice && payloadUserId == me && me.isNotEmpty()) return Action.OwnAccount
        return if (onOwnTopic && event in own) Action.OwnAccount else Action.None
    }
}
