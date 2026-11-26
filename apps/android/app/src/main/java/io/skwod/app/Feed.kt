package io.skwod.app

import android.util.Base64
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * The Feed and Stories are REAL E2EE content — the Android peer of iOS `Feed.swift`. Each post/story
 * is a normal channel message in its server's feed channel, tagged so the chat view hides it and the
 * feed shows it. Comments and likes ride the same Sender-Key channel path, so the server only ever
 * sees ciphertext. Wire tags + JSON are byte-compatible with iOS/macOS.
 */
private const val FEED_TAG = "skwod/feed|"
private const val STORY_TAG = "skwod/story|"
private const val COMMENT_TAG = "skwod/comment|"
/**
 * Retired: a channel message is never an address announcement. Anyone in a channel could post
 * one, so a move is only ever accepted as a record signed by the pinned instance key
 * (`AppModel.checkAddressRecord`). The tag is kept solely so old messages stay hidden from chat.
 */
const val ADDR_TAG = "skwod/addr|"
/** A "like" is a reaction whose (sealed) emoji is this marker. The server sees only a keyed tag. */
private const val LIKE_EMOJI = "like"

/** True if a channel message belongs to the Feed (hidden from chat). */
fun isFeedHidden(body: String): Boolean =
    body.startsWith(FEED_TAG) || body.startsWith(STORY_TAG) || body.startsWith(COMMENT_TAG) || body.startsWith(ADDR_TAG) ||
        AvatarStore.isAvatarMessage(body) || isGameContent(body)

data class FeedItem(
    val id: String,
    val author: String,
    val mine: Boolean,
    val text: String,
    /** The SMALL inline preview that travels in the message body (or, on posts from builds ≤ 42, the whole picture). */
    val photo: ByteArray?,
    val createdAt: Long,
    var liked: Boolean = false,
    var likes: Int = 0,
    var commentCount: Int = 0,
    /** The server this post lives in, and that server's feed channel (likes and comments go there). */
    val serverId: String = "",
    val channelId: String = "",
    val serverName: String = "",
    /** The full picture: an E2EE attachment linked to the post, fetched when it is shown. */
    val attachment: ChatAttachment? = null,
    /** A song shared with the post or story (a post may be nothing but a song). */
    val music: MusicTrack? = null,
    /** Which part of the song a STORY plays (null: a post, or a story from a build before 45). */
    val clip: MusicClip? = null,
)

/** A post or story that did not go out, kept so "Try again" sends exactly what was made. */
class FeedDraft(val story: Boolean, val text: String, val photo: ByteArray?, val music: MusicTrack?, val clip: MusicClip?, val serverId: String?)

data class FeedComment(
    val id: String, val postId: String, val author: String, val mine: Boolean,
    val text: String, val createdAt: Long,
)

/**
 * Client-backed Feed + Stories, over the E2EE channel.
 *
 * Every server has ONE feed channel, the same on every device (`feedChannel(serverId)`): posting,
 * liking, commenting and reading all happen there — never in "whichever channel is first on
 * this device", which differed from member to member. The feed shows the posts of every server
 * the user is in; a new post goes to the server picked in the composer ([postServerId]).
 *
 * A picture is an attachment (uploaded once, linked to the post with its blob id) plus a small
 * inline thumbnail in the body. The full picture never rides inline: a body over the wire limit
 * is refused by the core, and that refusal — like every other failed send — is reported
 * ([error]) instead of vanishing.
 */
class FeedModel(private val model: AppModel, private val chat: AppChat) {
    val posts = mutableStateListOf<FeedItem>()
    val stories = mutableStateListOf<FeedItem>()
    val commentsByPost = mutableStateMapOf<String, List<FeedComment>>()
    var loading by mutableStateOf(false)
    /** Why the last post / story / comment / like did not go out. Shown until dismissed. */
    var error by mutableStateOf<String?>(null)
    /** A post or story is on its way out, and how far along it is. Nothing else is accepted meanwhile. */
    var sending by mutableStateOf<FeedSend?>(null)
        private set
    /** What did not go out, until it is retried or discarded ([error] says why). */
    var failedDraft by mutableStateOf<FeedDraft?>(null)
        private set
    private val memberNames = HashMap<String, String>()
    /** The workspace [memberNames] was read from (one skwod's names are never another's). */
    private var namesFor: String? = null

    /** The servers the user is in, as (server id, name) — the composer's picker. */
    val servers: List<Pair<String, String>>
        get() = chat.serverGroups().filter { it.serverId.isNotEmpty() && it.serverId != "demo" }.map { it.serverId to it.name }
    /** Where a new post or story goes; null = the first server. */
    var postServerId by mutableStateOf<String?>(null)
    val targetServer: Pair<String, String>? get() = servers.firstOrNull { it.first == postServerId } ?: servers.firstOrNull()
    val hasSpace: Boolean get() = servers.isNotEmpty()

    /** The realtime topics of the feed channels read so far (the view refreshes on their events). */
    @Volatile var topics: Set<String> = emptySet()
        private set

    suspend fun refresh() {
        // Everything below is asked of ONE workspace's client; what it answers is filed only
        // while that same binding is still up ([Asked.holds]).
        val asked = model.bound ?: return
        val client = asked.client
        val me = model.current?.userId ?: return
        if (namesFor != asked.workspaceId) { memberNames.clear(); namesFor = asked.workspaceId }
        val all = servers
        if (all.isEmpty()) { posts.clear(); stories.clear(); commentsByPost.clear(); return }
        loading = true
        try {
            // The server's clock, not this phone's: a story is 24 hours of SERVER time old.
            val now = try { withContext(Dispatchers.IO) { client.serverNowMs() } } catch (_: Exception) { System.currentTimeMillis() }
            val newPosts = ArrayList<FeedItem>()
            val newStories = ArrayList<FeedItem>()
            val newComments = HashMap<String, MutableList<FeedComment>>()
            val seenTopics = HashSet<String>()
            var reached = false
            for ((sid, serverName) in all) {
                val listed = try { withContext(Dispatchers.IO) { client.listMembers(sid) } } catch (_: Exception) { emptyList() }
                if (!Asked.holds(asked, model.bound)) return
                listed.forEach { memberNames[it.userId] = it.username }
                val cid = chat.feedChannel(sid) ?: continue
                seenTopics.add("channel:$cid")
                var msgs = try { withContext(Dispatchers.IO) { client.fetchChannelMessages(cid, me) } } catch (_: Exception) { continue }
                reached = true
                // Stories past their day END: other people's leave this device's cache, mine
                // are deleted for everyone (and their photos with them).
                val ended = try { withContext(Dispatchers.IO) { client.expireStories(cid, STORY_TAG, StoryClock.TTL_MS) } } catch (_: Exception) { 0u }
                if (ended > 0u) msgs = try { withContext(Dispatchers.IO) { client.history("channel:$cid") } } catch (_: Exception) { msgs }
                val serverPosts = ArrayList<FeedItem>()
                for (m in msgs) {
                    if (m.isDeleted) continue
                    val body = m.content ?: ""
                    when {
                        body.startsWith(FEED_TAG) -> decode(body.substring(FEED_TAG.length), m, sid, cid, serverName)?.let { serverPosts.add(it) }
                        body.startsWith(STORY_TAG) -> decode(body.substring(STORY_TAG.length), m, sid, cid, serverName)?.let {
                            if (StoryClock.live(it.createdAt, now)) newStories.add(it)
                        }
                        body.startsWith(COMMENT_TAG) -> decodeComment(body.substring(COMMENT_TAG.length), m)?.let {
                            newComments.getOrPut(it.postId) { ArrayList() }.add(it)
                        }
                    }
                }
                // Likes: every reaction of the channel in one cache read, not one request per post.
                val reactions = try { withContext(Dispatchers.IO) { client.channelReactions(cid) } } catch (_: Exception) { emptyList() }
                val likes = reactions.filter { it.emoji == LIKE_EMOJI }.groupBy { it.messageId }
                for (p in serverPosts) {
                    val l = likes[p.id] ?: emptyList()
                    newPosts.add(p.copy(likes = l.size, liked = l.any { it.userId == me }))
                }
            }
            // A server that held an answer across a workspace switch: none of it is shown as the
            // other skwod's feed.
            if (!Asked.holds(asked, model.bound)) return
            topics = seenTopics
            model.drainDmEvents()                       // those fetches may have drained the mailbox
            if (!reached) return                        // offline: keep what is on screen
            newComments.values.forEach { it.sortBy { c -> c.createdAt } }
            commentsByPost.clear(); newComments.forEach { (k, v) -> commentsByPost[k] = v }
            posts.clear()
            posts.addAll(newPosts.map { it.copy(commentCount = newComments[it.id]?.size ?: 0) }.sortedByDescending { it.createdAt })
            stories.clear(); stories.addAll(newStories.sortedByDescending { it.createdAt })
        } finally { loading = false }
    }

    /** Post to the picked server's feed. Returns true when it went out; otherwise [error] says why. */
    suspend fun post(text: String, photo: ByteArray?, music: MusicTrack? = null): Boolean =
        send(FeedDraft(false, text, photo, music, null, targetServer?.first))
    /** [clip]: which part of the song plays (ignored without a song). */
    suspend fun postStory(photo: ByteArray?, music: MusicTrack? = null, clip: MusicClip? = null): Boolean =
        send(FeedDraft(true, "", photo, music, clip.takeIf { music != null }, targetServer?.first))

    /** Send what failed again, exactly as it was made (to the server it was meant for). */
    suspend fun retryFailed(): Boolean { val d = failedDraft ?: return false; return send(d) }

    /** Give up on what failed. */
    fun discardFailed() { failedDraft = null; error = null }

    private suspend fun send(draft: FeedDraft): Boolean {
        // One at a time: a second tap while the first is still uploading posts nothing.
        if (sending != null) return false
        // Where it goes and through what is settled here, at the tap ([Compose]).
        val from = Compose.sender(model.bound, chat.spacesWorkspaceId)
        val store = model.blobStore()
        val target = draft.serverId ?: targetServer?.first
        sending = FeedSend(if (draft.photo == null) FeedSend.Stage.SENDING else FeedSend.Stage.ENCRYPTING, story = draft.story)
        failedDraft = null
        try {
            Uploads.refreshLimit(model)
            val ok = send(from, store, target, if (draft.story) STORY_TAG else FEED_TAG, draft, if (draft.story) "Couldn't add your story" else "Couldn't post")
            if (!ok) failedDraft = draft
            return ok
        } finally { sending = null }
    }

    /** Delete a post, a story or a comment of mine, for everyone (queued; its photo goes too). */
    suspend fun delete(messageId: String, channelId: String) {
        val client = model.client ?: run { error = "Couldn't delete that — not connected."; return }
        if (channelId.isEmpty()) return
        try { withContext(Dispatchers.IO) { client.queueChannelDelete(channelId, messageId) } }
        catch (e: Exception) { error = failure("Couldn't delete that", e); return }
        posts.removeAll { it.id == messageId }; stories.removeAll { it.id == messageId }
        commentsByPost.keys.toList().forEach { k -> commentsByPost[k] = commentsByPost[k].orEmpty().filter { it.id != messageId } }
        Outbox.kick(model)
    }

    private fun failure(what: String, e: Exception): String = when (e) {
        is AttachmentException -> e.message ?: "$what — the picture couldn't be uploaded."
        // "That message is too big to send…": the core's own sentence.
        is uniffi.skwod_core.CoreException.Invalid -> HistoryWindow.sendError(e.detail, "$what.")
        is uniffi.skwod_core.CoreException.UpdateRequired -> "$what — update Skwod first."
        else -> "$what — check your connection and try again."
    }

    private suspend fun send(from: BoundClient<uniffi.skwod_core.SkwodClient>?, store: BlobStore?, target: String?, tag: String, draft: FeedDraft, what: String): Boolean {
        val (text, photo, music) = Triple(draft.text, draft.photo, draft.music)
        error = null
        val client = from?.client ?: run { error = "$what — not connected."; return false }
        val sid = target ?: run { error = "$what — join a server first."; return false }
        val cid = (if (model.bound?.workspaceId == from.workspaceId) chat.feedChannel(sid) else null) ?: run { error = "$what — couldn't reach this server's feed. Check your connection."; return false }
        try {
            val payload = JSONObject()
            if (text.isNotEmpty()) payload.put("text", text)
            val blobIds = ArrayList<String>()
            if (photo != null) {
                if (store == null) { error = "$what — not connected."; return false }
                // The picture itself: pixels only, sealed, uploaded once, linked to the post.
                val full = FeedMedia.downscaledJpeg(photo) ?: run { error = "$what — that picture couldn't be read."; return false }
                val up = AttachmentService.uploadImageBytes(full, store, thumbMaxDimension = FeedMedia.THUMB_DIMENSION,
                    // Called from the upload's thread; Compose state is safe to set from any thread.
                    onProgress = { share -> sending = sending?.advancedTo(share) })
                sending = sending?.copy(stage = FeedSend.Stage.SENDING)
                blobIds.add(up.blobId)
                // In the body: only a small preview (what builds ≤ 42 show), and the descriptor.
                up.attachment.thumbB64?.let { payload.put("photoB64", it) }
                // Key `att`, the same as the Apple app writes — a post reads the same everywhere.
                payload.put("att", JSONObject(up.attachment.copy(thumbB64 = null).toJson()))
            }
            // A song: the same `music` object the Apple app writes and reads.
            music?.let { payload.put("music", JSONObject(it.toJson())) }
            // A story's clip: which part of the song's preview plays. Beside `music`, the same
            // object the Apple app writes — inside the encrypted body, never seen by the host.
            if (music != null) draft.clip?.let { payload.put("clip", it.toJson()) }
            payload.put("ts", System.currentTimeMillis())
            // Queued, so a post written on a train is not lost: it is in the feed at once and
            // reaches everyone when the connection is back.
            try {
                withContext(Dispatchers.IO) { client.queueChannelMessage(cid, tag + payload.toString(), null, blobIds, emptyList()) }
                Outbox.kick(model)
            }
            catch (e: Exception) {
                // Uploaded but never posted: take the picture off the host again.
                blobIds.forEach { store?.delete(it) }
                throw e
            }
        } catch (e: Exception) { error = failure(what, e); return false }
        refresh()
        return true
    }

    suspend fun comment(post: FeedItem, text: String): Boolean {
        error = null
        val client = Compose.sender(model.bound, chat.spacesWorkspaceId)?.client ?: run { error = Compose.OPENING; return false }
        val t = text.trim(); if (t.isEmpty()) return false
        val cid = post.channelId.ifEmpty { chat.feedChannel(post.serverId) ?: "" }
        if (cid.isEmpty()) { error = "Couldn't comment — this post's server can't be reached."; return false }
        val payload = JSONObject().apply { put("postId", post.id); put("text", t); put("ts", System.currentTimeMillis()) }
        try {
            withContext(Dispatchers.IO) { client.queueChannelMessage(cid, COMMENT_TAG + payload.toString(), null, emptyList(), emptyList()) }
            Outbox.kick(model)
        } catch (e: Exception) { error = failure("Couldn't comment", e); return false }
        refresh()
        return true
    }

    suspend fun toggleLike(item: FeedItem) {
        val client = model.client ?: return
        val i = posts.indexOfFirst { it.id == item.id }; if (i < 0) return
        val cid = posts[i].channelId.ifEmpty { return }
        val willLike = !posts[i].liked
        posts[i] = posts[i].copy(liked = willLike, likes = maxOf(0, posts[i].likes + if (willLike) 1 else -1))
        try {
            withContext(Dispatchers.IO) { client.queueReaction(cid, item.id, LIKE_EMOJI, !willLike) }
            Outbox.kick(model)
        } catch (e: Exception) {
            val j = posts.indexOfFirst { it.id == item.id }
            if (j >= 0) posts[j] = posts[j].copy(liked = !willLike, likes = maxOf(0, posts[j].likes + if (willLike) -1 else 1))
            error = failure(if (willLike) "Couldn't like that post" else "Couldn't remove your like", e)
        }
    }

    private fun decode(json: String, m: uniffi.skwod_core.Message, serverId: String, channelId: String, serverName: String): FeedItem? = try {
        val o = JSONObject(json)
        val mine = (m.authorId ?: "") == "__me__" || m.authorId == model.current?.userId
        // Member names are the server's word: shown through the contact book (marked if unverified).
        val author = if (mine) "you" else model.contacts.shown(m.authorId, m.authorId?.let { memberNames[it] } ?: (m.authorId ?: "member").take(6)).label
        // The server's time for the message — what expiry and ordering are judged by. (`ts`
        // inside the body is the sender's claim and is ignored.)
        val ts = m.createdAt
        // A shared song: shown only through the Apple-host allowlist ([MusicTrack.safeUrl]).
        val music = o.optJSONObject("music")?.let { MusicTrack.fromJson(it.toString()) }
        // The descriptor is the sender's: it must name an image, and nothing else is taken from it here.
        val att = (o.optJSONObject("att") ?: o.optJSONObject("attachment"))?.let { ChatAttachment.fromJson(it.toString()) }?.takeIf { it.kind == "image" }
        FeedItem(m.messageId, author, mine, o.optString("text", ""),
            if (o.has("photoB64")) Base64.decode(o.getString("photoB64"), Base64.NO_WRAP) else null, ts,
            serverId = serverId, channelId = channelId, serverName = serverName, attachment = att, music = music,
            clip = if (music != null) MusicClip.inPayload(o) else null)
    } catch (_: Exception) { null }

    private fun decodeComment(json: String, m: uniffi.skwod_core.Message): FeedComment? = try {
        val o = JSONObject(json)
        val mine = (m.authorId ?: "") == "__me__" || m.authorId == model.current?.userId
        // Member names are the server's word: shown through the contact book (marked if unverified).
        val author = if (mine) "you" else model.contacts.shown(m.authorId, m.authorId?.let { memberNames[it] } ?: (m.authorId ?: "member").take(6)).label
        val ts = m.createdAt      // the server's time, not the sender's `ts`
        FeedComment(m.messageId, o.getString("postId"), author, mine, o.getString("text"), ts)
    } catch (_: Exception) { null }
}

/** The feed's picture sizes: what is uploaded as the attachment, and the small inline preview. */
object FeedMedia {
    /** Bounded decode, orientation applied, pixels only (no EXIF/GPS) — see [SafeImage]. */
    fun downscaledJpeg(data: ByteArray, maxDimension: Int = 1080, quality: Int = 50): ByteArray? =
        SafeImage.jpeg(data, maxDimension, quality)

    /** The inline preview that rides in a post's body: small enough to never matter (~10–20 KB). */
    const val THUMB_DIMENSION = 320
}
