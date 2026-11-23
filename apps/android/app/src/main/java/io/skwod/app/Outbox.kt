package io.skwod.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Where a message of mine stands on its way out. A delivered message has no state. */
sealed interface SendState {
    data object Sending : SendState
    /** The server refused it (or it cannot go out as it is): shown with Retry / Discard. */
    data class Failed(val localId: String, val reason: String) : SendState
}

/**
 * Pure rules for reading the core's outbox (no android.*, no FFI — unit-tested).
 *
 * Everything a person sends — chat, posts, stories, comments, game moves, forwards, edits,
 * deletes, reactions, and their DM counterparts — is queued in the core (`queue…`) and delivered
 * when the network allows, once. A queued SEND has a row to hang its state on ("Sending…" /
 * "Not sent"); a failed edit, delete or reaction has none, so its sentence is reported once and
 * the entry is dropped.
 */
object OutboxPolicy {
    data class Row(val localId: String, val messageId: String, val kind: String, val state: String, val error: String?)
    data class View(val byMessage: Map<String, SendState>, val problem: String?, val toDiscard: List<String>)

    fun view(rows: List<Row>): View {
        val states = LinkedHashMap<String, SendState>()
        var problem: String? = null
        val drop = ArrayList<String>()
        for (r in rows) {
            val failed = r.state == "failed"
            if (r.kind == "send") {
                states[r.messageId] = if (failed) SendState.Failed(r.localId, r.error?.takeIf { it.isNotBlank() } ?: "This message wasn't sent.") else SendState.Sending
            } else if (failed) {
                if (problem == null) problem = r.error?.takeIf { it.isNotBlank() } ?: "That change could not be made."
                drop += r.localId
            }
        }
        return View(states, problem, drop)
    }

    /** A sentence for a queueing failure (the core's own words when it has some). */
    fun queueError(detail: String?, fallback: String = "Couldn't send — try again."): String =
        detail?.takeIf { it.isNotBlank() }?.replaceFirstChar { it.uppercase() } ?: fallback
}

/** The app's thin side of the outbox: kick a flush, read the states. */
object Outbox {
    /** Bumped whenever something was queued, delivered or failed: open conversations redraw. */
    val revision = mutableIntStateOf(0)
    private val gate = Mutex()
    /** Messages the user composed that are waiting to be accepted (for the sent sound). */
    private val composedWaiting = java.util.concurrent.atomic.AtomicInteger(0)

    fun changed() { revision.intValue = revision.intValue + 1 }

    /** Deliver what is queued. Safe to call often (one flush runs at a time). */
    suspend fun flush(model: AppModel) {
        val c = model.client ?: return
        gate.withLock {
            val r = try { withContext(Dispatchers.IO) { c.flushOutbox() } } catch (_: Exception) { null }
            E2E.sawOutbox(r?.sent?.toInt() ?: 0, r?.pending?.toInt() ?: 0, r?.failed?.toInt() ?: 0)
            // The sent sound: when the server took something the user wrote — not on tap.
            val accepted = r?.sent?.toInt() ?: 0
            if (AlertPolicy.sentSound(composedWaiting.get(), accepted, model.settings.soundSent)) model.playSound(Sounds.SENT)
            if (accepted > 0 || (r != null && r.pending.toInt() == 0)) composedWaiting.set(0)
            // A send the server refused may mean this install is not the device any more
            // (removed, superseded): the report carries no type, so the state is re-read.
            if ((r?.failed ?: 0u) > 0u) model.routeDeviceState()
        }
        changed()
    }

    /**
     * Queue-and-go. [composed]: the user wrote and sent this (a message, an edit) — as opposed
     * to what the app queues by itself (likes, comments, game moves), which makes no sound.
     */
    fun kick(model: AppModel, composed: Boolean = false) {
        if (composed) composedWaiting.incrementAndGet()
        changed()
        model.launchIO { flush(model) }
    }

    /** States of the queued sends of `scope` (`channel:<id>` / `dm:<id>`), by message id. */
    suspend fun states(model: AppModel, scope: String): OutboxPolicy.View {
        val c = model.client ?: return OutboxPolicy.View(emptyMap(), null, emptyList())
        return withContext(Dispatchers.IO) {
            val rows = try { c.pendingSends(scope) } catch (_: Exception) { emptyList() }
            val view = OutboxPolicy.view(rows.map { OutboxPolicy.Row(it.localId, it.messageId, it.kind, it.state, it.error) })
            for (id in view.toDiscard) try { c.discardSend(id) } catch (_: Exception) {}
            view
        }
    }

    fun retry(model: AppModel, localId: String) = model.launchIO {
        try { model.client?.retrySend(localId) } catch (_: Exception) {}
        flush(model)
    }

    /** Try several failed sends again (a lifted hold), then one flush. */
    suspend fun retryAll(model: AppModel, localIds: List<String>) {
        if (localIds.isEmpty()) return
        val c = model.client ?: return
        withContext(Dispatchers.IO) { for (id in localIds) try { c.retrySend(id) } catch (_: Exception) {} }
        flush(model)
    }

    /**
     * Give up on a send. One that carries an attachment still being uploaded ([scope] and
     * [messageId] say which message) also releases that upload — the local ciphertext and
     * whatever part of it already reached the server.
     */
    fun discard(model: AppModel, localId: String, scope: String? = null, messageId: String? = null) = model.launchIO {
        if (scope != null && messageId != null) Uploads.releaseFor(model, scope, messageId)
        try { model.client?.discardSend(localId) } catch (_: Exception) {}
        changed()
    }
}

/**
 * People this account blocked. Blocking goes through the core (`blockUser`), which rotates this
 * device's delivery key, keeps the local drop list and leaves a blocked person out of everything
 * read from the cache — chat, feed, stories, comments, reactions, DMs. What the core does not read
 * for us is filtered with [ids]: live-message notifications and presence.
 */
object BlockList {
    var ids by mutableStateOf(setOf<String>())
        private set

    fun contains(userId: String?) = userId != null && userId in ids

    /** What this device already knows — no network. */
    fun adopt(model: AppModel) {
        ids = try { model.client?.blockedUserIds()?.toSet() ?: emptySet() } catch (_: Exception) { emptySet() }
    }

    /** From the server (a block made on another device applies here). At launch and on reconnect. */
    suspend fun refresh(model: AppModel) {
        val c = model.client ?: return
        val rows = try { withContext(Dispatchers.IO) { c.refreshBlocks() } } catch (_: Exception) { null }
        // The answer is the workspace's that was asked: it is not put up in another one.
        if (model.client !== c) return
        val before = ids
        if (rows != null) ids = rows.map { it.userId }.toSet() else adopt(model)
        if (ids != before) Outbox.changed()
    }

    /** Block or unblock; returns a sentence when it failed. */
    suspend fun setBlocked(model: AppModel, userId: String, name: String, blocked: Boolean): String? {
        val c = model.client ?: return "Not connected — try again in a moment."
        try {
            withContext(Dispatchers.IO) { if (blocked) c.blockUser(userId) else c.unblockUser(userId) }
        } catch (_: Exception) {
            return if (blocked) "Couldn't block $name — check your connection." else "Couldn't unblock $name — check your connection."
        }
        adopt(model)
        Outbox.changed()      // open conversations re-read history: the core now leaves them out
        return null
    }
}

/** Pure story rules (unit-tested): a story's age is SERVER time against the server's clock. */
object StoryClock {
    const val TTL_MS = 24L * 60 * 60 * 1000

    /** `createdAt` is the server's time for the message — never the `ts` its sender wrote. */
    fun live(createdAt: Long, serverNow: Long, ttl: Long = TTL_MS): Boolean = serverNow - createdAt < ttl
}

/** Report categories, the same list on every platform. */
object ReportCategories {
    val all = listOf(
        "harassment" to "Harassment or bullying", "spam" to "Spam", "illegal" to "Illegal content",
        "impersonation" to "Pretending to be someone", "other" to "Something else",
    )
}

/**
 * Which rows of a DM conversation a reply preview may quote (pure, unit-tested): live messages
 * written by me or by the ONE peer the conversation is bound to. A row by anyone else — a
 * third account filed under this conversation id, a system notice — is never quoted, so it
 * cannot appear under the peer's name.
 */
object DmReplyPolicy {
    fun mine(authorId: String?, me: String?): Boolean = authorId == "__me__" || (me != null && authorId == me)

    fun quotable(authorId: String?, deleted: Boolean, me: String?, peer: String): Boolean =
        !deleted && authorId != null && (mine(authorId, me) || authorId == peer)

    /** The same rule for a group: only what one of its members (or I) wrote can be quoted. */
    fun quotable(authorId: String?, deleted: Boolean, me: String?, members: Collection<String>): Boolean =
        !deleted && authorId != null && (mine(authorId, me) || authorId in members)
}
