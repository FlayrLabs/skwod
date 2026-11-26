package io.skwod.app

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * DEBUG-only automation hooks for end-to-end checks on an emulator — the Android peer of the
 * Apple app's `E2EHooks.swift` (see docs/APPLE.md "Proving it"; the second participant is
 * `core/skwod-core/examples/e2e_peer.rs`). This file lives in the `debug` source set;
 * release builds compile the empty stub in `src/release` instead.
 *
 * The emulator is driven by `adb shell setprop debug.skwod.e2e.<name> <value>` (the `debug.`
 * namespace is writable by the shell and readable by apps). The real paths still run: the invite
 * arrives through the `skwod://` intent filter, sign-up goes through the connect screen's own
 * submit code, messages go through the same client calls the UI makes.
 *
 * | Property | Effect |
 * |---|---|
 * | `user`, `password` | once an invite is in the connect form, fill these in and submit |
 * | `send` | send this text to the first channel (again whenever the value changes) |
 * | `call` | `1`: open the first server's call |
 * | `camera` | `1`: turn the camera on once the call is connected |
 * | `cmd` | one build-44 command, run again whenever the value changes: `queue:<text>` (queue a message to the first channel, as the composer does), `flush`, `block:<username>`, `unblock:<username>`, `report:<username>` (their newest message there, quoted) — and the account / content commands listed below |
 * | `norecoveryprompt` | `1`: the first-run recovery-key sheet stays away |
 *
 * Build-44 commands (same names as the Apple app's hooks; each outcome lands in `results`):
 * `devices` (list + max + state), `renamedevice:<name>`, `removedevice:<name or id prefix>`,
 * `signout`, `erasecheck`, `erase` / `eraselost`, `recoverykey` (generate + enable; records the
 * key and when it becomes instant), `compromised`, `restore:<key>`, `retryrestore[:pin]`,
 * `fingerprint`, `recoveries` (restores waiting for this device's answer),
 * `approverecovery:<code>` / `blockrecovery:<code>`, `pinreset[:pin]`, `forgotpin`,
 * `applock:on|off|status`, `unlock`, `reports`, `reportaction:<remove|kick|ban|dismiss>` (on the
 * newest report), `groupdm:<user1>+<user2>:<text>`, `groups`, `upload:<path>` /
 * `dmupload:<user>:<path>`, `uploads`, `state` (device state + which full-screen state shows),
 * `notices` (the security activity list). `applock:on|off` and `unlock` flip the lock WITHOUT
 * the system prompt — that prompt cannot be driven; it is what the hook stands in for.
 *
 * State is written to `<external files>/e2e-state.json` (what this device could DECRYPT, who is
 * waiting to join its first server, how it is connected, whether the foreground service runs, call + tunnel counters) for `adb pull`.
 */
object E2E {
    private fun prop(name: String): String? = try {
        val p = ProcessBuilder("getprop", "debug.skwod.e2e.$name").redirectErrorStream(true).start()
        p.inputStream.bufferedReader().use { it.readText() }.trim().ifEmpty { null }
    } catch (_: Exception) { null }

    fun credentials(): Pair<String, String>? {
        val u = prop("user") ?: return null
        val p = prop("password") ?: return null
        return u to p
    }

    fun wantsCamera(): Boolean = prop("camera") == "1"

    /** `norecoveryprompt` = `1`: the first-run recovery-key sheet stays away (it would cover a driven run). */
    fun suppressRecoveryPrompt(): Boolean = prop("norecoveryprompt") == "1"

    // ---- build 44: outbox totals, reports filed, the last command's outcome ----
    @Volatile private var outboxSent = 0
    @Volatile private var outboxPending = 0
    @Volatile private var outboxFailed = 0
    private val reports = java.util.concurrent.CopyOnWriteArrayList<JSONObject>()
    private val results = java.util.concurrent.CopyOnWriteArrayList<JSONObject>()
    fun sawOutbox(sent: Int, pending: Int, failed: Int) { outboxSent += sent; outboxPending = pending; outboxFailed = failed }
    fun sawReport(id: String, sealed: Boolean) { reports.add(JSONObject().put("report_id", id).put("sealed_to_owner", sealed)) }

    /** What `state` reports: the core's device state and the full-screen state on screen. */
    private fun stateJson(model: AppModel): JSONObject = JSONObject()
        .put("device_state", model.lastDeviceState)
        .put("device_id", model.deviceId ?: JSONObject.NULL)
        .put("showing", when {
            AppLock.locked -> "locked"
            model.current == null -> "signed_out"
            model.stopped == InstallRoute.Screen.REMOVED -> "removed"
            model.stopped == InstallRoute.Screen.SUPERSEDED -> "superseded"
            model.recoveryWaiting -> "waiting_to_restore"
            model.account.pinPrompt != null -> "pin"
            model.resetPending != null -> "reset_waiting"
            model.needsDeviceLink -> "set_up_this_device"
            model.account.recoveryRequests.isNotEmpty() -> "recovery_request"
            model.account.recoveryKeyPrompt != null -> "recovery_key"
            else -> "app"
        })
        .put("signed_out_by_user", JSONArray(model.workspaces.filter { it.signedOutByUser }.map { it.displayName }))
        .put("workspaces", model.workspaces.size)

    private fun outcomeText(o: AccountFlows.RestoreOutcome): String = when (o) {
        AccountFlows.RestoreOutcome.Restored -> "restored"
        AccountFlows.RestoreOutcome.Waiting -> "waiting"
        AccountFlows.RestoreOutcome.Pin -> "pin"
        AccountFlows.RestoreOutcome.NoBackup -> "no backup"
        AccountFlows.RestoreOutcome.WrongKey -> "wrong key"
        is AccountFlows.RestoreOutcome.Failed -> "failed: ${o.why}"
    }

    /** Commands that need no channel (and some no device): accounts, devices, recovery, lock. */
    private suspend fun accountCommand(name: String, arg: String, model: AppModel, ctx: Context): String? {
        // These work with no engine at all.
        when (name) {
            "state" -> return stateJson(model).toString()
            "applock" -> return when (arg) {
                "on" -> { model.settings.appLock = true; AppLock.set(true); "on locked=true" }
                "off" -> { model.settings.appLock = false; AppLock.set(false); "off" }
                else -> "enabled=${model.settings.appLock} locked=${AppLock.locked} after=${model.settings.appLockMinutes}m secure=${AppLock.available(ctx)}"
            }
            "unlock" -> { AppLock.set(false); return "locked=${AppLock.locked}" }
            "signout" -> { val another = model.leaveCurrent(); return "ok another=$another kept=${model.workspaces.count { it.signedOutByUser }}" }
        }
        val client = model.client ?: return if (name in ACCOUNT_COMMANDS) "error: no engine" else null
        val account = model.account
        return when (name) {
            "devices" -> {
                val list = client.listDevices()
                JSONObject().put("max", list.maxDevices.toInt()).put("state", model.lastDeviceState)
                    .put("devices", JSONArray(list.devices.map { d ->
                        JSONObject().put("id", d.deviceId).put("name", d.name ?: JSONObject.NULL).put("this", d.isThisDevice)
                            .put("verified", d.verified).put("created_at", d.createdAt).put("last_active_at", d.lastActiveAt) }))
                    .put("erased", JSONArray(client.erasedDevices().map { it.deviceId })).toString()
            }
            "renamedevice" -> { client.renameDevice(DeviceLabel.cleaned(arg)); account.accountChanged(); "ok" }
            "removedevice" -> {
                val rows = client.listDevices().devices.map { DeviceRows.Row(it.deviceId, it.name, it.createdAt, it.lastActiveAt, it.isThisDevice, it.verified) }
                val target = DeviceRows.find(rows.filter { !it.isThisDevice }, arg) ?: return "error: no such device"
                client.unregisterDevice(target.deviceId)
                account.recoveryKeyPrompt = RecoveryKeyReason.DEVICE_REMOVED
                account.accountChanged()
                "ok removed=${target.deviceId}"
            }
            "erasecheck" -> client.eraseCheck().let { "safe=${it.safe} backup=${it.hasKeyBackup} other_devices=${it.otherDevices.toInt()}" }
            "erase", "eraselost" -> { val another = model.eraseThisDevice(asLost = name == "eraselost", evenIfOffline = false); "ok another=$another workspaces=${model.workspaces.size}" }
            "recoverykey" -> {
                val key = uniffi.skwod_core.generateRecoveryKey()
                client.enableKeyBackup(key)
                account.recoveryKeyPrompt = null; account.revision.intValue++
                JSONObject().put("key", key).put("instant_from", client.recoveryKeyInstantFrom() ?: JSONObject.NULL)
                    .put("tail_ok", RecoveryKeyCheck.matches(RecoveryKeyCheck.tail(key), key)).toString()
            }
            "compromised" -> { client.reportRecoveryKeyCompromised(); account.recoveryKeyPrompt = RecoveryKeyReason.COMPROMISED; account.accountChanged(); "ok backup=${client.keyBackupEnabled()}" }
            "restore" -> outcomeText(account.restore(arg)) + " state=${model.lastDeviceState}"
            "retryrestore" -> outcomeText(account.retryRestore(arg.ifEmpty { null })) + " state=${model.lastDeviceState}"
            "fingerprint" -> JSONObject().put("code", client.recoveryFingerprint()).put("completes_at", client.recoveryCompletesAt() ?: JSONObject.NULL)
                .put("contested", client.recoveryContested()).toString()
            "recoveries" -> { account.accountChanged(); JSONArray((account.recoveryRequests + account.deferred).map {
                JSONObject().put("device_id", it.deviceId).put("request_id", it.requestId).put("code", it.fingerprint) }).toString() }
            "approverecovery", "blockrecovery" -> {
                // By the CODE the waiting device shows — the same check a person makes — and then
                // by that request's own id.
                val match = RecoveryRequests.matching(account.recoveryRequests + account.deferred, arg)
                if (match.size != 1) "error: ${match.size} requests match that code"
                else account.answer(match[0], approve = name == "approverecovery").let { (kind, line) -> "${kind.name.lowercase()}: $line" }
            }
            "pinreset" -> (account.resetDevices(arg.ifEmpty { null }) ?: "ok") + " state=${model.lastDeviceState} pin_prompt=${account.pinPrompt?.message ?: account.pinPrompt?.purpose ?: "none"} waiting=${model.resetPending != null}"
            "forgotpin" -> (account.resetForgotPin() ?: "ok") + " waiting=${model.resetPending ?: "no"}"
            "notices" -> { account.loadActivity(); JSONArray(account.activity.map {
                JSONObject().put("kind", it.kind).put("title", it.title).put("message", it.message).put("at_ms", it.atMs) }).toString() }
            "reports" -> { model.syncDmsNow(); model.reports.refresh(); JSONArray(model.reports.list.map { r ->
                val target = model.reports.resolve(r) as? ReportRules.Resolution.Target
                JSONObject().put("report_id", r.reportId).put("reporter", r.reporterUserId).put("subject", r.subjectUserId ?: JSONObject.NULL)
                    .put("category", r.category).put("note", r.note ?: JSONObject.NULL).put("excerpt", r.excerpt ?: JSONObject.NULL)
                    .put("channel_id", r.channelId ?: JSONObject.NULL).put("message_id", r.messageId ?: JSONObject.NULL)
                    .put("found_on_device", target != null).put("match", model.reports.match(r, target).name.lowercase())
                    // What the actions would really touch — resolved on this device, not read off the report.
                    .put("resolved_author", target?.authorId ?: JSONObject.NULL).put("resolved_server", target?.serverId ?: JSONObject.NULL)
                    .put("warnings", JSONArray(target?.warnings ?: emptyList<String>())) }).toString() }
            "reportaction" -> {
                model.reports.refresh()
                val newest = model.reports.list.firstOrNull() ?: return "error: no reports"
                // Only ever the resolved target: the hook has no way to pick a person by hand.
                when (arg) {
                    "remove" -> model.reports.remove(newest)
                    "kick" -> model.reports.moderate(newest, ban = false)
                    "ban" -> model.reports.moderate(newest, ban = true)
                    "dismiss" -> model.reports.dismiss(newest)
                    else -> "unknown action"
                } ?: "ok left=${model.reports.list.size}"
            }
            "groups" -> { model.groups.refresh(); JSONArray(model.groups.list.map { g ->
                JSONObject().put("conversation_id", g.conversationId).put("title", model.groups.title(g)).put("others", JSONArray(g.others))
                    .put("messages", client.history("dm:${g.conversationId}").count { !it.isSystem }) }).toString() }
            "groupdm" -> {
                val names = arg.substringBefore(':').split('+').map { it.trim() }.filter { it.isNotEmpty() }
                val text = arg.substringAfter(':', "")
                val ids = names.map { client.findUser(it).userId }
                val group = model.groups.open(ids)
                client.queueDm(group.conversationId, group.others, text, null, emptyList())
                Outbox.flush(model)
                "ok conversation=${group.conversationId} title=${model.groups.title(group)}"
            }
            "dmupload" -> {
                val who = arg.substringBefore(':'); val path = arg.substringAfter(':', "")
                val found = client.findUser(who)
                val convo = client.openDm(found.userId)
                val up = Uploads.prepare(ctx, model, model.bound ?: return "error: no client", android.net.Uri.fromFile(File(path)), forDm = true)
                client.queueDm(convo, listOf(found.userId), up.body, null, listOf(up.uploadId))
                Uploads.watch(model); Outbox.flush(model)
                "ok upload=${up.uploadId} size=${up.attachment.size} token=${up.attachment.token != null}"
            }
            "uploads" -> JSONArray(client.pendingUploads().map {
                JSONObject().put("upload_id", it.uploadId).put("blob_id", it.blobId ?: JSONObject.NULL).put("sent", it.sent.toLong())
                    .put("total", it.total.toLong()).put("done", it.done) }).toString()
            else -> null
        }
    }

    private val ACCOUNT_COMMANDS = setOf("devices", "renamedevice", "removedevice", "erasecheck", "erase", "eraselost", "recoverykey", "compromised",
        "restore", "retryrestore", "fingerprint", "recoveries", "approverecovery", "blockrecovery", "pinreset", "forgotpin", "notices", "reports",
        "reportaction", "groups", "groupdm", "dmupload", "uploads")

    private suspend fun command(cmd: String, model: AppModel, ctx: Context) {
        val name = cmd.substringBefore(':')
        val arg = cmd.substringAfter(':', "")
        val outcome = try {
            accountCommand(name, arg, model, ctx) ?: run {
                // The rest act on the first channel, as the composer would.
                val client = model.client ?: return@run "error: no engine"
                val me = model.current?.userId ?: return@run "error: not signed in"
                val space = model.chat.spaces.firstOrNull() ?: return@run "error: no channel yet"
                val channelId = space.channelId; val serverId = space.serverId
                when (name) {
                    "queue" -> { client.queueChannelMessage(channelId, arg, null, emptyList(), emptyList()); Outbox.flush(model); "ok" }
                    "flush" -> { Outbox.flush(model); "pending=${client.pendingSends(null).size}" }
                    "block", "unblock" -> {
                        val found = client.findUser(arg)
                        BlockList.setBlocked(model, found.userId, arg, name == "block") ?: "ok"
                    }
                    "report" -> {
                        val found = client.findUser(arg)
                        val target = client.fetchChannelMessages(channelId, me).lastOrNull { it.authorId == found.userId && !it.isDeleted && !it.isSystem && !it.isUndecryptable }
                        // As the message menu does: with where the message is.
                        val r = client.reportMessageAt("harassment", null, target?.content, found.userId, serverId, channelId, target?.messageId)
                        sawReport(r.reportId, r.sealedToOwner)
                        "ok sealed=${r.sealedToOwner} quoted=${target != null}"
                    }
                    "upload" -> {
                        val up = Uploads.prepare(ctx, model, model.bound ?: return@run "error: no client", android.net.Uri.fromFile(File(arg)), forDm = false)
                        client.queueChannelMessage(channelId, up.body, null, emptyList(), listOf(up.uploadId))
                        Uploads.watch(model); Outbox.flush(model)
                        "ok upload=${up.uploadId} size=${up.attachment.size}"
                    }
                    else -> "unknown"
                }
            }
        } catch (e: Exception) { "error: ${coreErrorKind(e) ?: e.javaClass.simpleName}: ${coreErrorDetail(e) ?: e.message}" }
        results.add(JSONObject().put("command", cmd).put("result", outcome))
    }

    suspend fun drive(model: AppModel, ctx: Context) = withContext(Dispatchers.IO) {
        if (prop("user") == null && prop("send") == null && prop("call") == null && prop("cmd") == null) return@withContext
        val out = File(ctx.getExternalFilesDir(null), "e2e-state.json")
        var lastSent: String? = null
        var lastCmd: String? = null
        var called = false
        while (true) {
            delay(2000)
            val client = model.client
            val me = model.current?.userId
            val state = JSONObject()
            // A command runs whatever the app is showing — locked, signed out, waiting to restore.
            val cmd = prop("cmd")
            if (cmd != null && cmd != lastCmd) { lastCmd = cmd; command(cmd, model, ctx) }
            state.put("install", stateJson(model))
            state.put("results", JSONArray(results.toList()))
            state.put("connection", model.connection.title)
            state.put("p2p", model.current?.isP2P ?: false)
            state.put("signedIn", me != null)
            state.put("deviceRegistered", model.deviceId != null)
            state.put("pinFailed", model.pinFailed)
            state.put("serviceRunning", ConnectionService.running)
            state.put("foreground", model.appForeground)
            state.put("call", JSONObject().apply {
                put("phase", CallDebug.phase); put("remoteParticipants", CallDebug.remoteParticipants)
                put("remoteVideoTracks", CallDebug.remoteVideoTracks); put("remoteAudioTracks", CallDebug.remoteAudioTracks)
                put("keysRegistered", CallDebug.keysRegistered); put("cameraOn", CallDebug.cameraOn)
            })
            model.current?.nodeId?.let { node ->
                P2PManager.session(node)?.let { s ->
                    val v = s.voiceStats()
                    state.put("voiceTunnel", JSONObject().apply {
                        put("packetsUp", v.packetsUp.toLong()); put("bytesUp", v.bytesUp.toLong())
                        put("packetsDown", v.packetsDown.toLong()); put("bytesDown", v.bytesDown.toLong())
                    })
                }
            }
            val space = model.chat.spaces.firstOrNull()
            if (client != null && me != null && model.deviceId != null && space != null) {
                state.put("channel", space.channelName)
                // Keys for whoever is in the channel now (what opening the channel in the UI does).
                try { client.syncChannelMembership(space.channelId, space.serverId, me) } catch (_: Exception) {}
                val text = prop("send")
                if (text != null && text != lastSent) {
                    try { client.sendChannelMessage(space.channelId, text); lastSent = text } catch (_: Exception) {}
                }
                state.put("outbox", JSONObject().put("sent", outboxSent).put("pending", outboxPending).put("failed", outboxFailed))
                state.put("reports_sent", JSONArray(reports.toList()))
                state.put("blocked", JSONArray(BlockList.ids.sorted()))
                // Who this device is holding back (no trusted approval, so no keys) and who asked to join.
                try {
                    model.waiting.refresh(space.serverId)
                    val waiting = JSONArray()
                    for (w in model.waiting.waiting(space.serverId)) {
                        waiting.put(JSONObject().put("userId", w.userId).put("username", w.username).put("source", w.source.name.lowercase()))
                    }
                    state.put("waiting", waiting)
                } catch (_: Exception) {}
                if (!called && prop("call") == "1") { called = true; model.answeredCallServer = space.serverId }
                try {
                    val rows = client.fetchChannelMessages(space.channelId, me)
                    val arr = JSONArray()
                    for (m in rows) {
                        val body = m.content ?: continue
                        // What the row is comes from its flags; a body that only LOOKS like a
                        // system row or a placeholder is a message and is listed as one.
                        if (m.isSystem || m.isUndecryptable) continue
                        if (body.isNotEmpty() && body[0].code < 0x20) continue
                        arr.put(JSONObject().put("mine", m.authorId == me || m.authorId == "__me__").put("text", body).put("at", m.createdAt))
                    }
                    state.put("messages", arr)
                } catch (_: Exception) {}
            }
            try { out.writeText(state.toString(2)) } catch (_: Exception) {}
        }
    }
}
