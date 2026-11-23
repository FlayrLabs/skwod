package io.skwod.app

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Rect
import android.util.Base64
import androidx.compose.runtime.mutableStateOf
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import uniffi.skwod_core.Message
import java.io.ByteArrayOutputStream

/**
 * End-to-end-encrypted avatars (profile pics, server icons, skwod icons) — the Android peer of the
 * Apple AvatarStore. An avatar is a small square JPEG carried, base64-encoded, inside a
 * `skwod/avatar|` tagged channel message: it rides the same Sender-Key E2EE path as every
 * other message, so the server only ever sees ciphertext. The tag carries the STX (U+0002) prefix
 * so it is byte-identical to iOS and avatars interoperate across platforms.
 *
 * Keys: `user:<userId>` · `server:<serverId>` · `skwod:<instanceId>`.
 */
class AvatarStore(private val model: AppModel) {
    companion object {
        const val TAG = "skwod/avatar|"
        const val SIDE = 256
        const val QUALITY = 60
        /** Bound cached avatars so members / ex-members don't grow memory unbounded. */
        private const val MAX_CACHED = 400
        fun userKey(userId: String) = "user:$userId"
        fun serverKey(serverId: String) = "server:$serverId"
        fun skwodKey(instanceId: String) = "skwod:$instanceId"
        fun isAvatarMessage(body: String) = body.startsWith(TAG)
    }

    /** avatarKey -> (raw square JPEG bytes, source timestamp). Persisted as-is (no re-encode). */
    private val raw = mutableStateOf<Map<String, Pair<ByteArray, Long>>>(emptyMap())
    /** The Compose-observed handle: bumped on every change so AvatarImage/AvatarTile recompose. */
    val images = raw
    /** Decoded-bitmap cache (lazy, keyed by identity of the raw bytes). */
    private val bmpCache = HashMap<String, Bitmap>()
    /** Newest ts SEEN per key, incl. clears (tombstone) — stops an old pointer resurrecting a clear. */
    private val seenTs = HashMap<String, Long>()
    private var loadedFor: String? = null

    /** The decoded bitmap for a key, if we hold one (decoded on demand + cached). */
    fun bitmap(key: String): Bitmap? {
        val (bytes, _) = raw.value[key] ?: return null
        bmpCache[key]?.let { return it }
        val bmp = SafeImage.decodeInbound(bytes, 512) ?: return null
        bmpCache[key] = bmp
        return bmp
    }


    // Persistence (per-workspace encrypted kv). Stores the RAW JPEG bytes, so nothing is re-encoded.

    suspend fun loadIfNeeded() {
        val wid = model.current?.id ?: return
        if (loadedFor == wid) return
        loadedFor = wid; gate.reset()
        raw.value = emptyMap(); bmpCache.clear(); seenTs.clear()
        val asked = model.bound?.takeIf { it.workspaceId == wid } ?: run { loadedFor = null; return }
        // A read that FAILS is not an empty store: nothing is written over it ([ReadGate]),
        // and the next call reads again.
        val json = try { asked.client.kvGet("$wid|avatars") } catch (_: Exception) { loadedFor = null; return }
        if (!Asked.holds(asked, model.bound) || loadedFor != wid) return
        gate.read(wid)
        if (json == null) return
        try {
            val obj = JSONObject(json)
            val map = HashMap<String, Pair<ByteArray, Long>>()
            for (k in obj.keys()) {
                val e = obj.getJSONObject(k)
                val bytes = try { Base64.decode(e.getString("b64"), Base64.NO_WRAP) } catch (_: Exception) { continue }
                if (!acceptable(bytes)) continue   // a cache written before avatars were bounded
                val t = e.getLong("ts")
                map[k] = bytes to t; seenTs[k] = t
            }
            raw.value = map
        } catch (_: Exception) {}
    }

    private val gate = ReadGate()

    private fun persist() {
        val snapshot = raw.value
        // Written through the client of the workspace these avatars belong to, under its key —
        // both taken NOW, not when the write runs — and only once its store was read.
        val bound = model.bound ?: return
        if (!gate.mayWrite(bound.workspaceId) || loadedFor != bound.workspaceId) return
        val key = "${bound.workspaceId}|avatars"
        model.launchIO {
            val obj = JSONObject()
            for ((k, v) in snapshot) {
                obj.put(k, JSONObject().put("b64", Base64.encodeToString(v.first, Base64.NO_WRAP)).put("ts", v.second))
            }
            try { bound.client.kvSet(key, obj.toString()) } catch (_: Exception) {}
        }
    }

    private fun evictIfNeeded(map: HashMap<String, Pair<ByteArray, Long>>) {
        if (map.size <= MAX_CACHED) return
        val myKey = model.current?.userId?.let { userKey(it) }
        map.entries.filter { it.key != myKey }.sortedBy { it.value.second }
            .take(map.size - MAX_CACHED).forEach { map.remove(it.key); bmpCache.remove(it.key) }
    }

    // Ingest: scan fetched channel messages for avatar pointers, adopt any newer than we hold.

    /**
     * The authority for messages carried by a channel of [serverId] in the active workspace:
     * that server's pinned owner and this instance's pinned owner — both from pins the core
     * holds, never from what the server lists.
     */
    suspend fun authority(serverId: String?): AvatarAuthority {
        val c = model.client ?: return AvatarAuthority()
        val instanceId = model.current?.instanceId
        val serverOwner = if (serverId.isNullOrEmpty()) null else try { withContext(Dispatchers.IO) { c.spaceOwner(serverId) } } catch (_: Exception) { null }
        val instanceOwner = if (instanceId == null) null else try { withContext(Dispatchers.IO) { c.instanceOwner() } } catch (_: Exception) { null }
        return AvatarAuthority(serverId, serverOwner, instanceId, instanceOwner)
    }

    /**
     * An embedded avatar is a 256 px JPEG of a few tens of kB. Anything much larger, or whose
     * header claims other than a small picture, is not stored — it would be decoded on every
     * screen that shows the sender, on every launch.
     */
    private fun acceptable(bytes: ByteArray): Boolean {
        if (!AvatarPolicy.acceptableSize(bytes.size)) return false
        val size = SafeImage.size(bytes) ?: return false
        return AvatarPolicy.acceptableDimensions(size.first, size.second)
    }

    /** [authority] says which server's channel carried these messages and who may speak for it. */
    fun ingest(messages: List<Message>, authority: AvatarAuthority) {
        var changed = false
        val map = HashMap(raw.value)
        val me = model.current?.userId
        val now = System.currentTimeMillis()
        for (m in messages) {
            val body = m.content ?: continue
            if (!body.startsWith(TAG)) continue
            val obj = try { JSONObject(body.substring(TAG.length)) } catch (_: Exception) { continue }
            val key = obj.optString("key"); if (key.isEmpty()) continue
            val t = obj.optLong("ts")
            // Only the user themself may set a user avatar; only the pinned owner of THE SERVER
            // THAT CARRIED THE MESSAGE its icon; only the instance owner the skwod icon. A pointer
            // dated in the future is dropped (it would outrank every later honest update).
            if (!AvatarPolicy.mayWrite(key, m.authorId, me, authority) || !AvatarPolicy.plausible(t, now)) continue
            // Tombstone: only strictly-newer pointers win, so an old one can't resurrect a clear.
            if ((seenTs[key] ?: 0) >= t) continue
            seenTs[key] = t
            val img = obj.optString("img", "")
            if (img.isNotEmpty()) {
                // Oversized or not a small picture: skipped (the timestamp still advances, so an
                // older good avatar is not resurrected over a newer bad one).
                if (img.length > AvatarPolicy.MAX_AVATAR_BYTES * 4 / 3 + 4) continue
                val bytes = try { Base64.decode(img, Base64.NO_WRAP) } catch (_: Exception) { continue }
                if (!acceptable(bytes)) continue
                map[key] = bytes to t; bmpCache.remove(key); changed = true
            } else if (map.containsKey(key)) {
                map.remove(key); bmpCache.remove(key); changed = true   // cleared
            }
        }
        if (changed) { evictIfNeeded(map); raw.value = map; persist() }
    }

    // Set (broadcast to the relevant channels).

    suspend fun setUserAvatar(imageData: ByteArray) {
        val me = model.current?.userId ?: return
        broadcast(userKey(me), imageData, allMyChannelIds())
    }

    suspend fun setServerAvatar(serverId: String, imageData: ByteArray) {
        broadcast(serverKey(serverId), imageData, channelIds(serverId))
    }

    suspend fun setSkwodAvatar(instanceId: String, imageData: ByteArray) {
        broadcast(skwodKey(instanceId), imageData, allMyChannelIds())
    }

    suspend fun clearAvatar(key: String, channelIds: List<String>) {
        broadcast(key, null, channelIds)
    }

    private suspend fun broadcast(key: String, imageData: ByteArray?, channelIds: List<String>) {
        val client = model.client ?: return
        val now = System.currentTimeMillis()
        val square = imageData?.let { withContext(Dispatchers.Default) { squareJpeg(it) } }
        val obj = JSONObject().put("key", key).put("ts", now)
        if (square != null) obj.put("img", Base64.encodeToString(square, Base64.NO_WRAP))
        // Local echo + advance tombstone so a stale echo can't undo it.
        seenTs[key] = now
        val map = HashMap(raw.value)
        if (square != null) { map[key] = square to now; bmpCache.remove(key) } else { map.remove(key); bmpCache.remove(key) }
        raw.value = map; persist()
        val body = TAG + obj.toString()
        // Fan out to every channel — sequentially is fine on the IO scope, but skip empties/demo.
        for (cid in channelIds.filter { it.isNotEmpty() && it != "demo" }) {
            try { withContext(Dispatchers.IO) { client.sendChannelMessage(cid, body) } } catch (_: Exception) {}
        }
    }

    private fun allMyChannelIds(): List<String> =
        model.chat.spaces.map { it.channelId }.filter { it.isNotEmpty() && it != "demo" }.distinct()

    private fun channelIds(serverId: String): List<String> =
        model.chat.spaces.filter { it.serverId == serverId }.map { it.channelId }.filter { it.isNotEmpty() }

    /** Center-crop to a square + downscale to a JPEG suitable for embedding. */
    private fun squareJpeg(data: ByteArray): ByteArray? {
        // Bounded decode — the picked file is the user's own, but the bounds cost nothing.
        val src = SafeImage.decode(data, 1024) ?: return null
        val s = minOf(src.width, src.height)
        val left = (src.width - s) / 2; val top = (src.height - s) / 2
        val square = Bitmap.createBitmap(SIDE, SIDE, Bitmap.Config.ARGB_8888)
        Canvas(square).drawBitmap(src, Rect(left, top, left + s, top + s), Rect(0, 0, SIDE, SIDE), null)
        val stream = ByteArrayOutputStream()
        square.compress(Bitmap.CompressFormat.JPEG, QUALITY, stream)
        return stream.toByteArray()
    }
}

/**
 * Where a batch of messages came from and who is in charge there — everything an avatar
 * pointer's authority is checked against. Same shape as the Apple app's `AvatarStore.Authority`.
 */
data class AvatarAuthority(
    /** The server whose channel carried the messages. */
    val serverId: String? = null,
    /** That server's owner, pinned through a trustworthy provenance (`SkwodClient.spaceOwner`). */
    val serverOwner: String? = null,
    /** The instance id of the workspace the messages were fetched in. */
    val instanceId: String? = null,
    /** That instance's owner, pinned under the instance key (`SkwodClient.instanceOwner`). */
    val instanceOwner: String? = null,
)

/**
 * Who may set which avatar. Avatars ride ordinary channel messages, so without this check any
 * member could overwrite anyone's picture or the server icon by posting a pointer with their key.
 * Pure (no android.*): unit-tested on the JVM.
 */
object AvatarPolicy {
    /**
     * - `user:<id>`: only that user (this device's own rows carry the "__me__" author).
     * - `server:<id>`: only when `<id>` IS the server whose channel carried the message, and only
     *   its pinned owner. (Checking the owner alone let the owner of server A, who shares an
     *   instance with server B, overwrite B's icon from a channel in A.)
     * - `skwod:<id>`: only when `<id>` is this workspace's instance, and only the instance
     *   owner. A server owner is not the instance owner.
     * An unknown id or an unpinned owner (null) authorizes nobody.
     */
    fun mayWrite(key: String, authorId: String?, me: String?, authority: AvatarAuthority): Boolean {
        if (authorId.isNullOrEmpty()) return false
        val author = (if (authorId == "__me__") me else authorId)?.takeIf { it.isNotEmpty() } ?: return false
        fun bound(prefix: String, id: String?, owner: String?): Boolean =
            !id.isNullOrEmpty() && !owner.isNullOrEmpty() && key.removePrefix(prefix) == id && owner == author
        return when {
            key.startsWith("user:") -> key.removePrefix("user:") == author
            key.startsWith("server:") -> bound("server:", authority.serverId, authority.serverOwner)
            key.startsWith("skwod:") -> bound("skwod:", authority.instanceId, authority.instanceOwner)
            else -> false
        }
    }

    /** A pointer's timestamp is the sender's claim: nothing in the future beyond clock skew. */
    fun plausible(ts: Long, now: Long): Boolean = ts > 0 && ts <= now + 5 * 60 * 1000

    const val MAX_AVATAR_BYTES = 512 * 1024
    const val MAX_AVATAR_EDGE = 2048
    fun acceptableSize(bytes: Int): Boolean = bytes in 1..MAX_AVATAR_BYTES
    fun acceptableDimensions(width: Int, height: Int): Boolean = width in 1..MAX_AVATAR_EDGE && height in 1..MAX_AVATAR_EDGE
}
