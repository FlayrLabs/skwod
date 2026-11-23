package io.skwod.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.skwod_core.AbuseReport

/**
 * The reports inbox of the skwod's owner: reports that reached this device, sealed to it like a
 * direct message (they arrive with the mailbox sync). `reporterUserId` is authenticated; the
 * quoted excerpt is the reporter's claim of what was said, which only the owner's own copy of
 * the channel can back up.
 */
class ReportsInbox(private val model: AppModel) {
    /** Newest first. */
    var list by mutableStateOf<List<AbuseReport>>(emptyList())
        private set

    fun reset() { list = emptyList() }

    suspend fun refresh() {
        val c = model.client ?: return
        val rows = try { withContext(Dispatchers.IO) { c.receivedReports() } } catch (_: Exception) { return }
        val next = rows.sortedByDescending { it.receivedAt }
        if (next != list) list = next
    }

    /** The reported message as THIS device holds it, when the report says where it is. */
    suspend fun cached(report: AbuseReport): uniffi.skwod_core.Message? {
        val c = model.client ?: return null
        val channel = report.channelId?.takeIf { it.isNotEmpty() } ?: return null
        val message = report.messageId?.takeIf { it.isNotEmpty() } ?: return null
        return try { withContext(Dispatchers.IO) { c.cachedMessage("channel:$channel", message) } } catch (_: Exception) { null }
    }

    /** Channel id → server id, from this device's OWN space list (never from a report). */
    private fun channelServers(): Map<String, String> = model.chat.spaces.associate { it.channelId to it.serverId }

    /**
     * Whom and what this report's actions would touch, confirmed against this device's own
     * copy ([ReportRules.resolve]): the cached message's real author and the server its channel
     * belongs to here. The report's person / server are only compared with that.
     */
    suspend fun resolve(report: AbuseReport): ReportRules.Resolution {
        val row = cached(report)?.let { ReportRules.CachedRow(it.authorId, it.content ?: "", it.isDeleted, it.isSystem, it.isUndecryptable) }
        return ReportRules.resolve(report.subjectUserId, report.serverId, report.channelId, report.messageId, row, channelServers(), model.current?.userId)
    }

    /** How the quoted excerpt relates to this device's copy. */
    fun match(report: AbuseReport, target: ReportRules.Resolution.Target?): ReportRules.Match =
        ReportRules.match(report.excerpt, target != null, listOfNotNull(target?.text, target?.text?.let { ChatTags.parse(it).text }))

    /** "Remove message": only the message this device resolved, and only when the report agrees with it. */
    suspend fun remove(report: AbuseReport): String? {
        val c = model.client ?: return "Not connected — try again in a moment."
        // Resolved again at the moment of acting: what was on the card may have changed.
        val target = resolve(report) as? ReportRules.Resolution.Target ?: return "That message isn't on this device any more."
        if (!target.canRemove) return target.warnings.first()
        return attempt { withContext(Dispatchers.IO) { c.deleteChannelMessage(target.channelId, target.messageId) }; Outbox.changed() }
    }

    /**
     * Kick or ban. With [manual] null the target is the RESOLVED one — the cached message's
     * author, in the server its channel belongs to on this device — and a report that
     * disagrees with it is refused. [manual] (server id, user id) is the owner's own explicit
     * pick, checked against this account's servers and that server's member list.
     */
    suspend fun moderate(report: AbuseReport, ban: Boolean, manual: Pair<String, String>? = null): String? {
        val c = model.client ?: return "Not connected — try again in a moment."
        val me = model.current?.userId
        val (server, subject) = if (manual != null) {
            val members = try { withContext(Dispatchers.IO) { c.listMembers(manual.first) }.map { it.userId } } catch (_: Exception) { return "Couldn't read that server's members — check your connection." }
            if (!ReportRules.manualChoiceValid(manual.first, manual.second, channelServers().values, members, me)) return "That person isn't a member of that server."
            manual
        } else {
            val target = resolve(report) as? ReportRules.Resolution.Target ?: return "That message isn't on this device any more."
            if (!target.canModerate) return target.warnings.firstOrNull() ?: "There is nobody to act on."
            target.serverId to target.authorId!!
        }
        return attempt {
            if (ban) {
                withContext(Dispatchers.IO) { c.banMember(server, subject, ReportRules.banReason(report.category)) }
                model.rotateKeysAfterRemoval(server)
            } else if (!model.kickMember(server, subject)) throw IllegalStateException("Couldn't kick — only the owner can.")
        }
    }

    suspend fun dismiss(report: AbuseReport): String? {
        val c = model.client ?: return "Not connected — try again in a moment."
        return attempt { withContext(Dispatchers.IO) { c.dismissReport(report.reportId, report.reporterUserId) }; refresh() }
    }

    private suspend fun attempt(block: suspend () -> Unit): String? = try { block(); null } catch (e: Exception) {
        coreErrorDetail(e) ?: e.message?.takeIf { e is IllegalStateException } ?: "That didn't work — check your connection and try again."
    }
}
