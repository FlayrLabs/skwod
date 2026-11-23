package io.skwod.app

import android.content.Context
import android.graphics.Bitmap
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.skwod_core.decryptAttachment
import uniffi.skwod_core.encryptAttachment
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * End-to-end encrypted attachments — the Android peer of iOS `Attachments.swift`.
 *
 * Files never touch the server in the clear. Encryption is Signal's attachment scheme, done in the
 * shared Rust core (`encryptAttachment` / `decryptAttachment`): a fresh random key per file,
 * AES-256-CBC + HMAC-SHA256, the plaintext padded to size buckets so the blob length hides the real
 * size, and a SHA-256 digest of the ciphertext. Only ciphertext is uploaded to the blob store
 * (`/api/blobs`); the key, digest and blob id travel INSIDE the E2EE chat message body, so the
 * server can neither read nor swap the file. Identical on iOS/macOS.
 */

/** Body prefixes for special chat messages (same  scheme as the feed, but these SHOW in chat). */
object ChatTags {
    const val ATTACH = "skwod/attach|"
    const val MUSIC = "skwod/music|"

    data class Parsed(val text: String, val attachment: ChatAttachment?, val music: MusicTrack?)

    fun parse(body: String): Parsed {
        if (body.startsWith(ATTACH)) {
            val a = ChatAttachment.fromJson(body.substring(ATTACH.length))
            if (a != null) return Parsed(a.caption ?: "", a, null)
        }
        if (body.startsWith(MUSIC)) {
            val t = MusicTrack.fromJson(body.substring(MUSIC.length))
            if (t != null) return Parsed("", null, t)
        }
        return Parsed(body, null, null)
    }
}

/** The attachment descriptor carried (E2EE) in the message body. */
data class ChatAttachment(
    val name: String,
    val mime: String,
    val size: Long,
    val kind: String,          // image | video | audio | file
    val blobId: String,
    /** 64-byte key (AES-256 ‖ HMAC) when [digestB64] is set; a bare AES-GCM key on builds ≤ 40. */
    val keyB64: String,
    val thumbB64: String? = null,
    val caption: String? = null,
    /** SHA-256 of the uploaded ciphertext — binds this message to exactly that blob. */
    val digestB64: String? = null,
    /**
     * The blob's download token (direct messages only). A sealed DM leaves nothing on the server
     * that access could hang on, so whoever can read this descriptor presents the token instead
     * of a session. Absent on channel attachments: there the server links the blob to the message.
     */
    val token: String? = null,
) {
    fun toJson(): String = JSONObject().apply {
        put("name", name); put("mime", mime); put("size", size); put("kind", kind)
        put("blobId", blobId); put("keyB64", keyB64)
        digestB64?.let { put("digestB64", it) }
        thumbB64?.let { put("thumbB64", it) }; caption?.let { put("caption", it) }
        token?.let { put("token", it) }
    }.toString()

    companion object {
        fun fromJson(s: String): ChatAttachment? = try {
            val o = JSONObject(s)
            ChatAttachment(
                o.getString("name"), o.getString("mime"), o.getLong("size"), o.getString("kind"),
                o.getString("blobId"), o.getString("keyB64"),
                if (o.has("thumbB64")) o.getString("thumbB64") else null,
                if (o.has("caption")) o.getString("caption") else null,
                if (o.has("digestB64")) o.getString("digestB64") else null,
                if (o.has("token")) o.getString("token").takeIf { it.isNotEmpty() } else null,
            )
        } catch (_: Exception) { null }
    }
}

/** An Apple Music reference shared in chat. Android can't play it, but renders a card that opens it. */
data class MusicTrack(val title: String, val artist: String, val url: String?, val artworkUrl: String?, val previewUrl: String? = null, val id: String = "") {
    /** The card as every platform reads it (the Apple app's `MusicTrack` keys; `id` is required there). */
    fun toJson(): String = JSONObject().apply {
        put("id", id.ifEmpty { url ?: "$title|$artist" })
        put("title", title); put("artist", artist)
        url?.let { put("appleMusicURL", it) }
        artworkUrl?.let { put("artworkURL", it) }
        previewUrl?.let { put("previewURL", it) }
    }.toString()

    // Every URL in a music card is the sender's. Only Apple's own hosts are ever opened or
    // fetched (same allowlist as the Apple app) — anything else is simply not offered.
    val safeUrl: String? get() = MusicHosts.safe(url)
    val safeArtworkUrl: String? get() = MusicHosts.safe(artworkUrl)
    val safePreviewUrl: String? get() = MusicHosts.safe(previewUrl)

    companion object {
        fun fromJson(s: String): MusicTrack? = try {
            val o = JSONObject(s)
            MusicTrack(o.optString("title", "Song"), o.optString("artist", ""),
                if (o.has("url")) o.getString("url") else o.optString("appleMusicURL", null),
                if (o.has("artworkUrl")) o.getString("artworkUrl") else o.optString("artworkURL", null),
                if (o.has("previewUrl")) o.getString("previewUrl") else o.optString("previewURL", null),
                o.optString("id", ""))
        } catch (_: Exception) { null }
    }
}

object AttachmentCrypto {
    private const val NONCE = 12
    private const val TAG_BITS = 128

    /** Sealed blob + what the message must carry to open it. */
    class Sealed(val ciphertext: ByteArray, val keyB64: String, val digestB64: String)

    /** Encrypt under a fresh key (shared core). */
    fun seal(data: ByteArray): Sealed {
        val e = encryptAttachment(data)
        return Sealed(e.ciphertext, Base64.encodeToString(e.key, Base64.NO_WRAP), Base64.encodeToString(e.digest, Base64.NO_WRAP))
    }

    /** Verify + decrypt a downloaded blob for attachment [a]. */
    fun open(blob: ByteArray, a: ChatAttachment): ByteArray {
        val key = Base64.decode(a.keyB64, Base64.NO_WRAP)
        val digest = a.digestB64 ?: return openLegacyGcm(blob, key)
        return decryptAttachment(blob, key, Base64.decode(digest, Base64.NO_WRAP), a.size.coerceAtLeast(0).toULong())
    }

    /** Attachments sent by pre-libsignal builds (≤ 40): single-shot AES-256-GCM. Read-only path. */
    private fun openLegacyGcm(combined: ByteArray, key: ByteArray): ByteArray {
        val iv = combined.copyOfRange(0, NONCE)
        val ctAndTag = combined.copyOfRange(NONCE, combined.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
        return cipher.doFinal(ctAndTag)
    }
}

/** Thin client for the server's resumable blob store; content is opaque ciphertext to the server. */
class BlobStore(private val base: String, private val token: String) {
    private fun conn(path: String, method: String): HttpURLConnection {
        val c = URL("${base.trimEnd('/')}/$path").openConnection() as HttpURLConnection
        c.requestMethod = method
        c.setRequestProperty("Authorization", "Bearer $token")
        c.connectTimeout = 15000; c.readTimeout = 30000
        return c
    }

    /** What the server said when it refused a request, as a sentence for the user. */
    private fun refusal(c: HttpURLConnection): AttachmentException {
        val status = try { c.responseCode } catch (_: Exception) { 0 }
        val body = try { c.errorStream?.bufferedReader()?.use { it.readText() } } catch (_: Exception) { null }
        return AttachmentException(BlobErrors.message(status, BlobErrors.errorField(body)))
    }

    /**
     * Create a blob and upload it in 1.5 MB chunks (safe under every deployed host's body limit).
     * [downloadTokenHash] (hex SHA-256 of a `newBlobDownloadToken()` token) registers a download
     * token with the blob — the direct-message path. A refusal (403 not in a space, 413 over the
     * account's quota, 507 host disk full, 429) is thrown with the server's own sentence.
     */
    suspend fun upload(data: ByteArray, downloadTokenHash: String? = null, onProgress: ((Float) -> Unit)? = null): String = withContext(Dispatchers.IO) {
        val create = conn("api/blobs", "POST")
        create.doOutput = true
        create.setRequestProperty("Content-Type", "application/json")
        val request = JSONObject().put("total_size", data.size)
        if (downloadTokenHash != null) request.put("download_token_hash", downloadTokenHash)
        try { create.outputStream.use { it.write(request.toString().toByteArray()) } }
        catch (_: java.io.IOException) { throw AttachmentException(BlobErrors.GENERIC) }
        if (create.responseCode != 200) throw refusal(create)
        val blobId = JSONObject(create.inputStream.bufferedReader().use { it.readText() }).getString("blob_id")

        val chunk = 1_500_000
        var offset = 0
        while (offset < data.size) {
            val end = minOf(offset + chunk, data.size)
            val patch = conn("api/blobs/$blobId", "PATCH")
            patch.doOutput = true
            patch.setRequestProperty("Upload-Offset", "$offset")
            patch.setRequestProperty("Content-Type", "application/offset+octet-stream")
            // Streamed (not buffered whole by the connection), so the count below is of bytes
            // that have really been handed to the network — the progress the feed shows.
            patch.setFixedLengthStreamingMode(end - offset)
            try {
                patch.outputStream.use { out ->
                    var at = offset
                    while (at < end) {
                        val n = minOf(64 * 1024, end - at)
                        out.write(data, at, n)
                        at += n
                        // Handed to the connection, not yet confirmed by the host: never the full amount.
                        onProgress?.invoke(minOf(FeedSend.IN_FLIGHT_CEILING, at.toFloat() / data.size.coerceAtLeast(1)))
                    }
                }
            }
            catch (_: java.io.IOException) { throw AttachmentException(BlobErrors.GENERIC) }
            if (patch.responseCode != 204) throw refusal(patch)
            offset = end
            onProgress?.invoke(offset.toFloat() / data.size.coerceAtLeast(1))   // the host has it
        }
        blobId
    }

    /** Why a story song's preview did not arrive. */
    class MusicPreviewException(val hostTooOld: Boolean) : Exception()

    /**
     * A story song's preview, fetched FOR this phone by its host (`POST /api/music/preview`) into
     * [dest]: the app never asks Apple itself. The URL goes in the body, so it is in no access log.
     */
    suspend fun musicPreview(url: String, dest: File) = withContext(Dispatchers.IO) {
        try {
            val c = conn("api/music/preview", "POST")
            c.connectTimeout = 10000; c.readTimeout = 25000
            c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json")
            c.outputStream.use { it.write(JSONObject().put("url", url).toString().toByteArray()) }
            when (c.responseCode) {
                200 -> {}
                404, 405 -> throw MusicPreviewException(hostTooOld = true)   // a host older than build 45
                else -> throw MusicPreviewException(hostTooOld = false)
            }
            if (c.contentType?.lowercase()?.startsWith("audio/") != true) throw MusicPreviewException(false)
            if (!AttachmentLimits.contentLengthOk(c.contentLengthLong, StoryMusicPolicy.MAX_PREVIEW_BYTES)) throw MusicPreviewException(false)
            c.inputStream.use { input -> dest.outputStream().use { out -> AttachmentLimits.copyBounded(input, out, StoryMusicPolicy.MAX_PREVIEW_BYTES) } }
        } catch (e: MusicPreviewException) { dest.delete(); throw e
        } catch (_: Exception) { dest.delete(); throw MusicPreviewException(false) }
    }

    /** `GET /api/instance/limits`, answered or not. */
    sealed class LimitAnswer {
        /** The host's per-file limit in bytes. */
        class Known(val bytes: Long) : LimitAnswer()
        /** The server does not know the question (older than build 45): the old fixed 100 MB. */
        object OldServer : LimitAnswer()
    }

    /** The largest file this skwod's host accepts; null when there was no answer (offline, signed out). */
    suspend fun uploadLimit(): LimitAnswer? = withContext(Dispatchers.IO) {
        try {
            val c = conn("api/instance/limits", "GET")
            c.connectTimeout = 8000; c.readTimeout = 8000
            when (c.responseCode) {
                200 -> UploadLimit.parse(c.inputStream.bufferedReader().use { it.readText().take(4096) })?.let { LimitAnswer.Known(it) }
                404, 405 -> LimitAnswer.OldServer
                else -> null
            }
        } catch (_: Exception) { null }
    }

    /**
     * Fetch a blob's ciphertext. With a [token] (the descriptor of a DM attachment carries one)
     * the token IS the credential: it goes in `x-skwod-blob-token` and NO Authorization header is
     * sent, so the server does not learn which account fetched it. Without one, the session.
     */
    suspend fun download(blobId: String, token: String? = null, maxBytes: Long = AttachmentLimits.maxCiphertext(UploadLimit.inMemoryDownloadCap())): ByteArray = withContext(Dispatchers.IO) {
        // Into memory: bounded by a fixed constant, never by what a server says it allows.
        @Suppress("NAME_SHADOWING") val maxBytes = minOf(maxBytes, AttachmentLimits.maxCiphertext(UploadLimit.inMemoryDownloadCap()))
        val c = URL("${base.trimEnd('/')}/api/blobs/$blobId").openConnection() as HttpURLConnection
        c.requestMethod = "GET"
        c.connectTimeout = 15000; c.readTimeout = 30000
        if (token != null) c.setRequestProperty("x-skwod-blob-token", token)
        else c.setRequestProperty("Authorization", "Bearer ${this@BlobStore.token}")
        val status = try { c.responseCode } catch (_: java.io.IOException) { throw AttachmentException("Download failed — check your connection.") }
        when (status) {
            200 -> {
                // The size is the SERVER's (and behind it the sender's) to claim. Refuse an
                // announced size over the cap before reading, and stop reading at the cap
                // whatever the header said — nothing of an oversized blob is kept.
                if (!AttachmentLimits.contentLengthOk(c.contentLengthLong, maxBytes)) {
                    c.disconnect()
                    throw AttachmentException("That file is larger than it claims to be, so it wasn't downloaded.")
                }
                try { c.inputStream.use { AttachmentLimits.readBounded(it, maxBytes) } }
                catch (_: AttachmentLimits.TooLarge) {
                    c.disconnect()
                    throw AttachmentException("That file is larger than it claims to be, so it wasn't downloaded.")
                }
                catch (_: java.io.IOException) { throw AttachmentException("Download failed — check your connection.") }
            }
            403, 404 -> throw AttachmentException("This file isn't available to you any more — it may have been deleted.")
            else -> throw AttachmentException("Download failed — check your connection.")
        }
    }

    /**
     * [download] straight to [dest] — for attachments, which can be large. The same rules: the
     * announced size is refused over the cap before a byte is read, reading stops at the cap
     * whatever the header said, and nothing partial is kept.
     */
    suspend fun downloadTo(blobId: String, dest: File, token: String? = null, maxBytes: Long = AttachmentLimits.maxCiphertext(UploadLimit.downloadCap())) = withContext(Dispatchers.IO) {
        val c = URL("${base.trimEnd('/')}/api/blobs/$blobId").openConnection() as HttpURLConnection
        c.requestMethod = "GET"
        c.connectTimeout = 15000; c.readTimeout = 30000
        if (token != null) c.setRequestProperty("x-skwod-blob-token", token)
        else c.setRequestProperty("Authorization", "Bearer ${this@BlobStore.token}")
        val status = try { c.responseCode } catch (_: java.io.IOException) { throw AttachmentException("Download failed — check your connection.") }
        when (status) {
            200 -> {
                if (!AttachmentLimits.contentLengthOk(c.contentLengthLong, maxBytes)) {
                    c.disconnect()
                    throw AttachmentException("That file is larger than it claims to be, so it wasn't downloaded.")
                }
                try {
                    c.inputStream.use { input -> dest.outputStream().use { out -> AttachmentLimits.copyBounded(input, out, maxBytes) } }
                } catch (_: AttachmentLimits.TooLarge) {
                    c.disconnect(); dest.delete()
                    throw AttachmentException("That file is larger than it claims to be, so it wasn't downloaded.")
                } catch (_: java.io.IOException) {
                    dest.delete()
                    throw AttachmentException("Download failed — check your connection.")
                }
            }
            403, 404 -> throw AttachmentException("This file isn't available to you any more — it may have been deleted.")
            else -> throw AttachmentException("Download failed — check your connection.")
        }
    }

    /** Remove a blob we uploaded (a DM attachment whose message was never sent). Best effort. */
    suspend fun delete(blobId: String) = withContext(Dispatchers.IO) {
        try { conn("api/blobs/$blobId", "DELETE").responseCode } catch (_: Exception) {}
        Unit
    }
}

class AttachmentException(message: String) : Exception(message)

object AttachmentService {
    const val MAX_BYTES = AttachmentLimits.MAX_BYTES.toInt()

    fun kind(mime: String): String = when {
        mime.startsWith("image/") -> "image"
        mime.startsWith("video/") -> "video"
        mime.startsWith("audio/") -> "audio"
        else -> "file"
    }

    /**
     * An uploaded attachment, ready to send: the tagged message [body] and the [blobId] it names.
     * A CHANNEL message must be sent with `sendChannelMessageWith(…, blobIds = [blobId])` so the
     * server links the blob to the message — otherwise only the uploader can open it. A DM
     * attachment is uploaded with `forDm = true` (its descriptor then carries a download token).
     */
    class Uploaded(val body: String, val blobId: String, val attachment: ChatAttachment) {
        val blobIds: List<String> get() = listOf(blobId)
    }

    /** Seal + upload [data]; for a DM, register a download token and put it in the descriptor. */
    private suspend fun sealAndUpload(data: ByteArray, name: String, mime: String, kind: String, thumb: String?, store: BlobStore, forDm: Boolean, onProgress: ((Float) -> Unit)? = null): Uploaded {
        val sealed = AttachmentCrypto.seal(data)
        val dl = if (forDm) uniffi.skwod_core.newBlobDownloadToken() else null
        val blobId = store.upload(sealed.ciphertext, dl?.hashHex, onProgress)
        val payload = ChatAttachment(name, mime, data.size.toLong(), kind, blobId, sealed.keyB64, thumb, null, sealed.digestB64, dl?.token)
        return Uploaded(ChatTags.ATTACH + payload.toJson(), blobId, payload)
    }

    /**
     * Seal + upload raw JPEG bytes in one go — the FEED's photo path only (a post's picture is
     * a bounded, re-encoded JPEG). Files and photos sent in chat go through [Uploads], which
     * streams them from disk and resumes.
     */
    suspend fun uploadImageBytes(picked: ByteArray, store: BlobStore, forDm: Boolean = false, thumbMaxDimension: Int = 480,
                                 onProgress: ((Float) -> Unit)? = null): Uploaded = withContext(Dispatchers.IO) {
        if (!UploadLimit.allowsUpload(picked.size.toLong(), inMemory = true)) throw AttachmentException(UploadLimit.tooLargeSentence(minOf(UploadLimit.current, UploadLimit.IN_MEMORY_BYTES)))
        // Pixels only — see uploadFile.
        val clean = SafeImage.stripped(picked) ?: throw AttachmentException("Couldn't prepare that photo for sending.")
        val data = clean.data
        val thumb = SafeImage.jpeg(data, thumbMaxDimension, 40)?.let { Base64.encodeToString(it, Base64.NO_WRAP) }
        sealAndUpload(data, "photo-${System.currentTimeMillis()}.${clean.extension}", clean.mime, "image", thumb, store, forDm, onProgress)
    }

    /** The most a legacy (in-memory) attachment may be. */
    private const val LEGACY_MAX_BYTES = 32L * 1024 * 1024

    /** The on-disk directory holding DECRYPTED attachment plaintext (cleartext at rest). */
    private fun cacheDir(ctx: Context): File = File(ctx.cacheDir, "skwod-attachments")

    /** Download + decrypt into a cached temp file (idempotent per blob), for players/openers. */
    suspend fun localFile(ctx: Context, a: ChatAttachment, store: BlobStore, maxBytes: Long = UploadLimit.downloadCap()): File = withContext(Dispatchers.IO) {
        // The declared size is the sender's claim: an oversized (or negative) one is refused
        // before anything is fetched. [maxBytes] is lower for downloads nobody asked for.
        if (!AttachmentLimits.acceptable(a.size, maxBytes)) {
            throw AttachmentException("That file is too large to open here (${formattedSize(a.size.coerceAtLeast(0))}; the limit is ${formattedSize(maxBytes)}).")
        }
        // App-private cache (never external storage), excluded from backup and device transfer by
        // the manifest's data-extraction rules; wiped at launch, sign-out, leave, and after 24 h.
        val dir = cacheDir(ctx).apply { mkdirs() }
        // `blobId` and `name` come from the sender: never let them shape the path or the URL.
        // The cached copy is named by what was VERIFIED (the descriptor's digest and key), so a
        // file cached for one descriptor is never handed back for another that reuses the blob
        // id and name ([AttachmentCache]).
        val dest = File(dir, AttachmentCache.fileName(a.blobId, a.name, a.digestB64, a.keyB64) ?: throw AttachmentException("Download failed."))
        if (dest.exists()) return@withContext dest
        // A descriptor with a token (DM attachment) is fetched with the token, not the session.
        // Never read more ciphertext than a file of the DECLARED size can be.
        val cap = AttachmentLimits.maxCiphertext(a.size)
        // Ciphertext goes to a file and is decrypted file-to-file by the core: a 100 MB video
        // is never held in memory. Nothing is written to [dest] unless the whole blob verifies
        // against the digest and key in the (end-to-end encrypted) descriptor.
        val blob = File(dir, "${a.blobId}.part")
        val out = File(dir, "${a.blobId}.plain")
        try {
            store.downloadTo(a.blobId, blob, a.token, cap)
            // Checked again before any decryption work is spent on it.
            if (blob.length() > cap) throw AttachmentException("That file is larger than it claims to be, so it wasn't opened.")
            val digest = a.digestB64
            if (digest != null) {
                try {
                    uniffi.skwod_core.decryptAttachmentFile(blob.absolutePath, out.absolutePath,
                        Base64.decode(a.keyB64, Base64.NO_WRAP), Base64.decode(digest, Base64.NO_WRAP), a.size.coerceAtLeast(0).toULong())
                } catch (_: uniffi.skwod_core.CoreException) { throw AttachmentException("That file didn't match what the message described, so it wasn't opened.") }
            } else {
                // Sent by a pre-libsignal build (≤ 40): single-shot AES-GCM, small by the limits of its day.
                if (blob.length() > LEGACY_MAX_BYTES) throw AttachmentException("That file is too large to open here.")
                out.writeBytes(AttachmentCrypto.open(blob.readBytes(), a))
            }
            if (out.length() > maxBytes) throw AttachmentException("That file is too large to open here.")
            if (!out.renameTo(dest)) throw AttachmentException("Couldn't fetch the file.")
        } finally { blob.delete(); out.delete() }      // no ciphertext and no partial plaintext left behind
        dest
    }

    /**
     * Wipe every decrypted attachment left on disk. Called when local data is torn down (sign-out /
     * leaving a workspace) so E2EE attachments don't linger in cleartext in the cache after the user's
     * session ends. Best-effort and safe to call when the dir doesn't exist.
     */
    fun purgeCache(ctx: Context) {
        runCatching { cacheDir(ctx).deleteRecursively() }
    }

    /** Decrypted copies only exist while they are being viewed: nothing older than this stays. */
    private const val MAX_AGE_MS = 24L * 60 * 60 * 1000

    /**
     * Remove decrypted attachments older than 24 h (the app may run for days behind its
     * foreground service, so "wiped at launch" alone is not enough). Called on every foreground.
     */
    fun expireCache(ctx: Context) {
        val cutoff = System.currentTimeMillis() - MAX_AGE_MS
        runCatching { cacheDir(ctx).listFiles()?.forEach { if (it.lastModified() < cutoff) it.delete() } }
    }

    /** Whether the active connection is metered (cellular, a metered hotspot): be frugal on it. */
    fun isMetered(ctx: Context): Boolean = try {
        (ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? android.net.ConnectivityManager)?.isActiveNetworkMetered ?: true
    } catch (_: Exception) { true }

    fun formattedSize(bytes: Long): String = when {
        bytes >= 1_000_000_000 -> "%.1f GB".format(bytes / 1e9)
        bytes >= 1_000_000 -> "%.1f MB".format(bytes / 1e6)
        bytes >= 1000 -> "%.0f KB".format(bytes / 1e3)
        else -> "$bytes B"
    }

    private fun queryName(ctx: Context, uri: Uri): String? = try {
        ctx.contentResolver.query(uri, null, null, null, null)?.use { c ->
            val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
        }
    } catch (_: Exception) { null }

    /** A ≤480 px JPEG thumbnail (bounded decode, orientation applied, no metadata). */
    private fun downscaledJpegBase64(data: ByteArray): String? =
        SafeImage.jpeg(data, 480, 40)?.let { Base64.encodeToString(it, Base64.NO_WRAP) }

    internal fun videoThumbBase64(ctx: Context, uri: Uri): String? = try {
        val retriever = MediaMetadataRetriever()
        retriever.setDataSource(ctx, uri)
        val frame = retriever.getFrameAtTime(500_000)
        retriever.release()
        if (frame == null) null else {
            val max = 480
            val scale = minOf(1f, max.toFloat() / maxOf(frame.width, frame.height))
            val scaled = Bitmap.createScaledBitmap(frame, (frame.width * scale).toInt(), (frame.height * scale).toInt(), true)
            val out = ByteArrayOutputStream()
            scaled.compress(Bitmap.CompressFormat.JPEG, 40, out)
            Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)
        }
    } catch (_: Exception) { null }

    /** Embedded cover art from an audio file (ID3/MP4), downscaled — null if the file has none. */
    internal fun audioArtworkBase64(ctx: Context, uri: Uri): String? = try {
        val retriever = MediaMetadataRetriever()
        retriever.setDataSource(ctx, uri)
        val art = retriever.embeddedPicture
        retriever.release()
        if (art == null) null else downscaledJpegBase64(art)
    } catch (_: Exception) { null }
}
