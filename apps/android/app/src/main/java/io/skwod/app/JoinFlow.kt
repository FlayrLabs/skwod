package io.skwod.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
import org.json.JSONObject

/**
 * A join that has been started and is not finished: the invite's code, where it leads, and how
 * far it got. Persisted (encrypted, with the session tokens) so that killing the app between
 * "account created" and "joined", or while waiting for the host's approval, loses nothing — the
 * next launch picks it up where it stopped.
 */
data class PendingJoinRecord(
    /** The workspace it belongs to; empty until the account exists on this device (see [JoinFlow.bind]). */
    val workspaceId: String,
    /** The skwod's stored address (`https://…` or `skwod://join/<node id>`). */
    val address: String,
    /** The account name the join was started with (binds an unbound record to its workspace). */
    val username: String,
    val code: String,
    /** The server the code leads to, once the host has told us. */
    val serverId: String? = null,
    val stage: Stage = Stage.NOT_SENT,
    val createdAt: Long = 0,
) {
    enum class Stage {
        /** The code has not been presented yet (signed up, then interrupted). */
        NOT_SENT,
        /** Presented; the host has to let us in. */
        REQUESTED,
        /** A member of the server; its keys have not arrived yet. */
        ADMITTED,
    }
}

/** JSON codec for the persisted list. Pure (org.json only), so it is unit-tested. */
object PendingJoinCodec {
    /** A join nobody answered for this long is dropped. */
    const val MAX_AGE_MS = 30L * 24 * 60 * 60 * 1000

    fun encode(records: List<PendingJoinRecord>): String = JSONArray().apply {
        for (r in records) put(JSONObject().apply {
            put("workspaceId", r.workspaceId); put("address", r.address); put("username", r.username)
            put("code", r.code); r.serverId?.let { put("serverId", it) }
            put("stage", r.stage.name); put("createdAt", r.createdAt)
        })
    }.toString()

    /** Malformed entries, entries without a valid code, and entries older than [MAX_AGE_MS] are dropped. */
    fun decode(json: String?, now: Long): List<PendingJoinRecord> {
        if (json.isNullOrBlank()) return emptyList()
        val arr = try { JSONArray(json) } catch (_: Exception) { return emptyList() }
        val out = ArrayList<PendingJoinRecord>()
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val code = o.optString("code")
            val address = o.optString("address")
            if (!InviteLink.isValidCode(code) || address.isEmpty()) continue
            val createdAt = o.optLong("createdAt", 0)
            if (createdAt <= 0 || now - createdAt > MAX_AGE_MS) continue
            val stage = try { PendingJoinRecord.Stage.valueOf(o.optString("stage")) } catch (_: Exception) { PendingJoinRecord.Stage.NOT_SENT }
            out.add(PendingJoinRecord(o.optString("workspaceId"), address, o.optString("username"), code,
                o.optString("serverId").takeIf { it.isNotEmpty() }, stage, createdAt))
        }
        return out
    }

    /** Attach records started before the account existed here to the workspace it became. */
    fun bound(records: List<PendingJoinRecord>, address: String, username: String, workspaceId: String): List<PendingJoinRecord> =
        records.map { if (it.workspaceId.isEmpty() && it.address == address && it.username == username) it.copy(workspaceId = workspaceId) else it }

    /** One record per (workspace, code): a newer one replaces an older one. */
    fun upsert(records: List<PendingJoinRecord>, r: PendingJoinRecord): List<PendingJoinRecord> =
        records.filterNot { it.code == r.code && it.workspaceId == r.workspaceId && it.address == r.address } + r
}

/** What the drawer shows about a join in progress. */
data class JoinStatus(val text: String, val problem: Boolean = false)

/**
 * Joining a server, made visible and durable. One coroutine per pending join walks it through:
 * present the code → (wait to be let in) → get the server's keys → channels appear. Each step
 * says what it is doing ([status]), survives a relaunch ([PendingJoinRecord]) and retries with
 * backoff instead of giving up quietly. The realtime events `join_approved` / `join_denied`
 * move it along at once; a slow check (every 25 s) covers a missed event.
 */
class JoinFlow(private val model: AppModel) {
    /** Shown above the channel list while a join is in flight, or after one failed. */
    var status by mutableStateOf<JoinStatus?>(null)

    private val jobs = HashMap<String, Job>()

    /** A join of [serverId] on the active skwod is being watched here. */
    fun isWatching(serverId: String): Boolean {
        val wid = model.current?.id ?: return false
        return load().any { it.workspaceId == wid && it.serverId == serverId && synchronized(jobs) { jobs["$wid|${it.code}"]?.isActive == true } }
    }
    private val approvals = Channel<String>(Channel.CONFLATED)
    private val lock = Any()

    private fun load(): List<PendingJoinRecord> =
        PendingJoinCodec.decode(model.secretGet(KEY), System.currentTimeMillis())
    private fun save(records: List<PendingJoinRecord>) = model.secretPut(KEY, if (records.isEmpty()) null else PendingJoinCodec.encode(records))
    private fun put(r: PendingJoinRecord) = synchronized(lock) { save(PendingJoinCodec.upsert(load(), r)) }
    private fun forget(r: PendingJoinRecord) = synchronized(lock) {
        save(load().filterNot { it.code == r.code && it.workspaceId == r.workspaceId })
    }

    /** Signing up with an invite: remember its code BEFORE the account is created. */
    fun remember(address: String, username: String, code: String) {
        if (code.isEmpty()) return
        put(PendingJoinRecord("", address, username, code, createdAt = System.currentTimeMillis()))
    }

    /** The sign-up was refused outright (bad invite, name taken): there is nothing to resume. */
    fun forgetUnbound(address: String, username: String, code: String) = synchronized(lock) {
        save(load().filterNot { it.workspaceId.isEmpty() && it.address == address && it.username == username && it.code == code })
    }

    /** The account now exists on this device as [workspaceId]. */
    fun bind(address: String, username: String?, workspaceId: String) {
        if (username == null) return
        synchronized(lock) { save(PendingJoinCodec.bound(load(), address, username, workspaceId)) }
    }

    /** A workspace was left / signed out: its joins go with it. */
    fun forgetWorkspace(workspaceId: String?) = synchronized(lock) {
        save(if (workspaceId == null) emptyList() else load().filterNot { it.workspaceId == workspaceId })
    }

    /** The active workspace changed: stop watching the old one's joins (their records stay). */
    fun reset() {
        synchronized(jobs) { jobs.values.forEach { it.cancel() }; jobs.clear() }
        status = null
    }

    /** Pick up every unfinished join of the active workspace (launch, reconnect, device linked). */
    fun resume() {
        val wid = model.current?.id ?: return
        for (r in load()) if (r.workspaceId == wid) start(r)
    }

    /** Join the active workspace's server behind [code] (a tapped invite the user confirmed). */
    fun begin(code: String) {
        val w = model.current ?: return
        val r = PendingJoinRecord(w.id, w.server, w.username ?: "", code, createdAt = System.currentTimeMillis())
        put(r); start(r, startedHere = true)
    }

    /**
     * "Join with a code": present it now so a wrong code is reported in the dialog. Returns the
     * sentence to show, or null when the join is under way (see [status] from here on).
     */
    suspend fun join(code: String): String? {
        val w = model.current ?: return "Not signed in."
        val client = model.client ?: return "Not signed in."
        if (!InviteLink.isValidCode(code)) return "That doesn't look like an invite code."
        var r = PendingJoinRecord(w.id, w.server, w.username ?: "", code, createdAt = System.currentTimeMillis())
        val result = try { client.joinByCode(code) } catch (e: Exception) {
            if (!isTransient(e)) return "Couldn't join — check the invite code."
            // The host did not answer. Keep the code and keep trying; say so.
            put(r); start(r, startedHere = true)
            return null
        }
        r = r.copy(serverId = result.serverId, stage = if (result.pending) PendingJoinRecord.Stage.REQUESTED else PendingJoinRecord.Stage.ADMITTED)
        model.chat.tombstones.rejoined(result.serverId)   // joined (again) on purpose
        put(r); start(r, startedHere = true)
        return null
    }

    /** [startedHere]: the user asked for it just now (not resumed): it may open the server, unless
     *  the host decides on it later ([Landing.joined]). */
    private fun start(r: PendingJoinRecord, startedHere: Boolean = false) {
        val key = "${r.workspaceId}|${r.code}"
        synchronized(jobs) {
            if (jobs[key]?.isActive == true) return
            jobs[key] = model.launchJob { run(r, startedHere) }
        }
    }

    /** A refusal the server will repeat (bad / used code, not allowed) as opposed to "no answer". */
    private fun isTransient(e: Exception): Boolean {
        val d = ((e as? uniffi.skwod_core.CoreException.Engine)?.detail ?: (e as? uniffi.skwod_core.CoreException.Invalid)?.detail ?: return true).lowercase()
        return !(listOf("400", "401", "403", "404", "409", "410", "422").any { d.contains(it) } || d.contains("invite") || d.contains("not found"))
    }

    private suspend fun run(start: PendingJoinRecord, startedHere: Boolean) {
        var r = start
        var opens = startedHere
        val alive = { model.current?.id == r.workspaceId && !model.pinFailed }
        // Joining asks members to hand keys to THIS device, so it needs its own keys first.
        var waited = 0
        while (alive() && (model.deviceId == null || model.client == null || model.baseUrl == null) && waited < 90) { delay(1000); waited++ }
        if (!alive()) return
        val c = model.client
        if (c == null || model.deviceId == null || model.baseUrl == null) {
            status = JoinStatus(
                if (model.needsDeviceLink) "Your invite is saved. Link this device to your account first — Skwod joins right after."
                else "Your invite is saved, but your host can't be reached yet. Skwod joins as soon as it can.", problem = true)
            return                                   // the record stays: resumed on reconnect / next launch
        }

        if (r.stage == PendingJoinRecord.Stage.NOT_SENT) {
            status = JoinStatus("Joining…")
            var result: uniffi.skwod_core.JoinResult? = null
            for (wait in Backoff.delays(6, 2_000, 60_000)) {
                if (!alive()) return
                try { result = c.joinByCode(r.code); break }
                catch (e: Exception) {
                    if (!isTransient(e)) {
                        forget(r)
                        // Possibly already presented before an interruption: whatever we are a
                        // member of is recovered; otherwise the code is simply no good.
                        val before = model.chat.spaces.size
                        model.chat.recoverMemberships()
                        status = if (model.chat.spaces.size > before) null
                            else JoinStatus("Couldn't join with that invite — it may have expired or been used. Ask your host for a fresh one.", problem = true)
                        return
                    }
                    status = JoinStatus("Couldn't reach your host to join. Trying again…", problem = true)
                    delay(wait)
                }
            }
            val joined = result
            if (joined == null) {
                status = JoinStatus("Couldn't reach your host to join. Skwod will try again when the connection is back.", problem = true)
                return
            }
            r = r.copy(serverId = joined.serverId, stage = if (joined.pending) PendingJoinRecord.Stage.REQUESTED else PendingJoinRecord.Stage.ADMITTED)
            model.chat.tombstones.rejoined(joined.serverId)   // joined (again) on purpose
            put(r)
        }
        val serverId = r.serverId ?: run { forget(r); status = null; return }

        if (r.stage == PendingJoinRecord.Stage.REQUESTED) {
            opens = false
            status = JoinStatus("Waiting for the host to let you in. You'll walk in as soon as they do — no need to keep this open.")
            // The `join_approved` event ends the wait at once; the slow check covers a missed one.
            while (alive()) {
                val mine = model.chat.memberServerIds()
                if (mine != null && serverId in mine) break
                if (!load().any { it.code == r.code && it.workspaceId == r.workspaceId }) return   // denied / forgotten
                withTimeoutOrNull(WATCH_MS) { while (approvals.receive() != serverId) { /* another server */ } }
            }
            if (!alive()) return
            r = r.copy(stage = PendingJoinRecord.Stage.ADMITTED)
            put(r)
        }

        // Admitted. The server's keys come from a member's device (the owner's, or one of our
        // own): ask, wait, and ask again — a failed hand-off is said out loud, never swallowed.
        status = JoinStatus("You're in. Getting this server's keys…")
        val waits = Backoff.delays(12, 5_000, 300_000)
        var round = 0
        while (alive()) {
            val asked = model.chat.askForKeys(serverId)
            if (model.chat.discover(serverId, asked.peerUserId, asked.peerDeviceId, joining = true, startedHere = opens, rounds = if (round == 0) 20 else 6)) {
                forget(r); status = null
                return
            }
            status = if (!asked.sent)
                JoinStatus("You're in, but Skwod couldn't ask anyone for this server's keys yet. Trying again…", problem = true)
            else JoinStatus("You're in, but this server's keys haven't arrived. They are handed over by a member who is online — your host's Skwod needs to be running. Still trying…", problem = true)
            delay(waits[round.coerceAtMost(waits.size - 1)])
            round++
        }
    }

    // ---- realtime (topic `user:<me>`) ----

    /** Someone asked to join a server I can approve people for: badge, list, notification. */
    suspend fun onJoinRequest(serverId: String, pending: Int) {
        if (serverId.isEmpty()) return
        model.waiting.refresh(serverId)
        model.notifier.joinRequest(serverId, pending)
    }

    /** My request was approved: walk in now. */
    suspend fun onApproved(serverId: String) {
        if (serverId.isEmpty()) return
        val wid = model.current?.id
        val mine = load().firstOrNull { it.workspaceId == wid && (it.serverId == serverId || it.stage == PendingJoinRecord.Stage.REQUESTED) }
        if (mine != null) { approvals.trySend(serverId); start(mine); return }
        // Asked from another of my devices (or before this build kept records): just recover it.
        model.chat.recoverMemberships()
    }

    /** My request was declined: say so, and stop waiting. */
    fun onDenied(serverId: String) {
        val wid = model.current?.id
        val mine = load().filter { it.workspaceId == wid && it.serverId == serverId }
        for (r in mine) {
            forget(r)
            synchronized(jobs) { jobs.remove("${r.workspaceId}|${r.code}")?.cancel() }
        }
        status = JoinStatus("The host declined your request to join.", problem = true)
        model.enqueueNotice(SecurityAlert("Not let in", "The host declined your request to join a server on ${model.current?.displayName ?: "this Skwod"}. If that was a mistake, ask them for a new invite."))
    }

    companion object {
        private const val KEY = "pending-joins"
        /** How often a pending request is re-checked when no event arrives. */
        const val WATCH_MS = 25_000L
    }
}
