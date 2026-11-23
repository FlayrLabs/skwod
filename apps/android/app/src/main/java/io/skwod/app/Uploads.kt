package io.skwod.app

import android.content.Context
import android.net.Uri
import android.util.Base64
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Streamed, resumable uploads through the core (FFI-CHANGES, "Uploads").
 *
 * Nothing here holds a whole file in memory. The picked item is copied to a private staging
 * file, the core encrypts it file-to-file into a work directory (`prepareUpload`, no network),
 * and the message that carries it is queued with the upload's id: the core uploads it at the
 * next flush — resuming from the server's offset after a dropped connection or an app restart —
 * and puts the real blob id into the message. The bubble shows the progress meanwhile.
 */
object Uploads {
    /** `pendingUploads()` as last polled, by upload id. */
    var progress by mutableStateOf<Map<String, UploadRules.Row>>(emptyMap())
        private set

    private var poller: Job? = null

    /**
     * Where the core keeps the CIPHERTEXT of uploads in flight, and where the PLAINTEXT copy of
     * a picked item sits for the moment it takes to encrypt it ([UploadPaths]): two separate
     * directories, both app-private and never backed up (`noBackupFilesDir`, and the manifest
     * excludes everything anyway), one of each per skwod.
     */
    private fun workDir(ctx: Context, workspaceId: String): File = UploadPaths.work(ctx.noBackupFilesDir, workspaceId).apply { mkdirs() }
    private fun stagingDir(ctx: Context, workspaceId: String): File = UploadPaths.staging(ctx.noBackupFilesDir, workspaceId).apply { mkdirs() }

    /**
     * At every launch, before anything can be picked: whatever is staged is a leftover of a
     * crash or a kill, and it is plaintext. (Also where builds before this one staged.)
     */
    fun sweepStaging(ctx: Context) { runCatching { UploadPaths.sweepStaging(ctx.noBackupFilesDir, listOf(File(ctx.cacheDir, "skwod-outgoing"))) } }

    /** A skwod is erased from this phone (erase, account deleted): its staged files and its uploads go. */
    fun purgeWork(ctx: Context, workspaceId: String) { runCatching { UploadPaths.purge(ctx.noBackupFilesDir, workspaceId) } }

    /** An attachment that is encrypted and tracked, ready to be queued with its message. */
    class Prepared(val body: String, val uploadId: String, val attachment: ChatAttachment)

    /**
     * A picked file → staged, (photos) stripped of metadata, encrypted by the core. The
     * descriptor names the blob by the core's placeholder; the body is `<tag>{json}` with that
     * placeholder as a whole string value, which is how the core later sets the real id.
     */
    suspend fun prepare(ctx: Context, model: AppModel, uri: Uri, forDm: Boolean): Prepared = withContext(Dispatchers.IO) {
        val resolver = ctx.contentResolver
        var mime = resolver.getType(uri) ?: "application/octet-stream"
        var name = queryName(ctx, uri) ?: "file"
        val wid = model.current?.id ?: throw AttachmentException("Not connected — the file wasn't sent.")
        // The host's per-file limit, as fresh as a minute: checked before anything is encrypted.
        refreshLimit(model)
        val limit = UploadLimit.current
        val staged = File(stagingDir(ctx, wid), "pick-${System.nanoTime()}")
        // The plaintext copy is deleted the moment it has been encrypted (or failed to be).
        try {
            val input = resolver.openInputStream(uri) ?: throw AttachmentException("Couldn't read the file.")
            try { input.use { copyBounded(it, staged, limit) } }
            catch (_: AttachmentLimits.TooLarge) { throw AttachmentException(UploadLimit.tooLargeSentence(limit)) }
            catch (_: java.io.IOException) { throw AttachmentException("Couldn't read the file.") }
            val kind = AttachmentService.kind(mime)
            var thumb: String? = null
            when (kind) {
                "image" -> {
                    // A photo has to be decoded to be re-encoded without its metadata, so this
                    // one kind is read whole — bounded, and only for pictures.
                    if (staged.length() > MAX_PHOTO_BYTES) throw AttachmentException("That photo is too large to prepare for sending.")
                    var data = staged.readBytes()
                    if (!SafeImage.sendAsIs(data)) {
                        // Pixels only: no GPS position, camera model or capture time. One that
                        // can't be re-encoded is refused rather than sent with what it carries.
                        val clean = SafeImage.stripped(data) ?: throw AttachmentException("Couldn't prepare that photo for sending.")
                        data = clean.data
                        staged.writeBytes(data)
                        if (clean.mime != mime) { mime = clean.mime; name = name.substringBeforeLast('.', name) + "." + clean.extension }
                    }
                    thumb = SafeImage.jpeg(data, 480, 40)?.let { Base64.encodeToString(it, Base64.NO_WRAP) }
                }
                "video" -> thumb = AttachmentService.videoThumbBase64(ctx, uri)
                "audio" -> thumb = AttachmentService.audioArtworkBase64(ctx, uri)
            }
            seal(ctx, model, staged, name, mime, kind, thumb, forDm)
        } finally { staged.delete() }
    }

    /**
     * A picture pasted from the clipboard, read whole so it can be previewed (and removed) before
     * Send — never more than the host's per-file limit or the photo cap. Sending it is then
     * [prepareImage], exactly like a camera photo (metadata stripped, encrypted, staged).
     */
    suspend fun readPastedImage(ctx: Context, model: AppModel, uri: Uri): ByteArray = withContext(Dispatchers.IO) {
        refreshLimit(model)
        val limit = UploadLimit.current
        val cap = minOf(limit, MAX_PHOTO_BYTES)
        val input = try { ctx.contentResolver.openInputStream(uri) } catch (_: Exception) { null }
            ?: throw AttachmentException("Couldn't read the picture on the clipboard. Copy it again, then paste.")
        val out = java.io.ByteArrayOutputStream()
        try {
            input.use { s ->
                val buf = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    val n = s.read(buf); if (n < 0) break
                    total += n
                    if (total > cap) throw AttachmentException(if (cap == limit) UploadLimit.tooLargeSentence(limit) else "That picture is too large to send.")
                    out.write(buf, 0, n)
                }
            }
        } catch (e: AttachmentException) { throw e
        } catch (_: Exception) { throw AttachmentException("Couldn't read the picture on the clipboard. Copy it again, then paste.") }
        out.toByteArray()
    }

    /** A photo from the camera (a bitmap's JPEG bytes): stripped, staged, encrypted. */
    suspend fun prepareImage(ctx: Context, model: AppModel, picked: ByteArray, forDm: Boolean): Prepared = withContext(Dispatchers.IO) {
        if (picked.size > MAX_PHOTO_BYTES) throw AttachmentException("That photo is too large.")
        val clean = SafeImage.stripped(picked) ?: throw AttachmentException("Couldn't prepare that photo for sending.")
        val wid = model.current?.id ?: throw AttachmentException("Not connected — the file wasn't sent.")
        val staged = File(stagingDir(ctx, wid), "photo-${System.nanoTime()}")
        try {
            staged.writeBytes(clean.data)
            val thumb = SafeImage.jpeg(clean.data, 480, 40)?.let { Base64.encodeToString(it, Base64.NO_WRAP) }
            seal(ctx, model, staged, "photo-${System.currentTimeMillis()}.${clean.extension}", clean.mime, "image", thumb, forDm)
        } finally { staged.delete() }
    }

    private suspend fun seal(ctx: Context, model: AppModel, staged: File, name: String, mime: String, kind: String, thumb: String?, forDm: Boolean): Prepared {
        val c = model.client ?: throw AttachmentException("Not connected — the file wasn't sent.")
        val wid = model.current?.id ?: throw AttachmentException("Not connected — the file wasn't sent.")
        val up = try { c.prepareUpload(staged.absolutePath, workDir(ctx, wid).absolutePath, forDm) }
            catch (e: uniffi.skwod_core.CoreException.Invalid) { throw AttachmentException(e.detail.ifBlank { "Couldn't prepare that file for sending." }) }
        val attachment = ChatAttachment(name, mime, up.plaintextLen.toLong(), kind, up.placeholderBlobId,
            Base64.encodeToString(up.key, Base64.NO_WRAP), thumb, null, Base64.encodeToString(up.digest, Base64.NO_WRAP), up.downloadToken)
        return Prepared(ChatTags.ATTACH + attachment.toJson(), up.uploadId, attachment)
    }

    /** The attachment was never queued (or its send was given up): drop it, and what reached the server. */
    suspend fun release(model: AppModel, uploadId: String) {
        try { withContext(Dispatchers.IO) { model.client?.releaseUpload(uploadId, true) } } catch (_: Exception) {}
    }

    /** A send is being discarded: release the upload its body still names, if any. */
    suspend fun releaseFor(model: AppModel, scope: String, messageId: String) {
        val c = model.client ?: return
        val body = try { withContext(Dispatchers.IO) { c.cachedMessage(scope, messageId) }?.content } catch (_: Exception) { null } ?: return
        val blobId = ChatTags.parse(body).attachment?.blobId ?: return
        UploadRules.uploadId(blobId)?.let { release(model, it) }
    }

    @Volatile private var limitAsked: Pair<String, Long>? = null

    /**
     * Keep [UploadLimit] in step with the skwod in front: asked at launch, on reconnect, and
     * before a file is checked when the last answer is more than a minute old.
     */
    suspend fun refreshLimit(model: AppModel, force: Boolean = false) {
        val wid = model.current?.id ?: return
        UploadLimit.activate(wid)
        val asked = limitAsked
        if (!force && asked != null && asked.first == wid && System.currentTimeMillis() - asked.second < 60_000) return
        when (val answer = model.blobStore()?.uploadLimit()) {
            is BlobStore.LimitAnswer.Known -> UploadLimit.learned(answer.bytes, wid)
            is BlobStore.LimitAnswer.OldServer -> UploadLimit.learned(null, wid)
            null -> return
        }
        limitAsked = wid to System.currentTimeMillis()
    }

    /** At launch and on reconnect: carry on with what was interrupted, then deliver its messages. */
    suspend fun resume(model: AppModel) {
        val c = model.client ?: return
        refreshLimit(model, force = true)
        watch(model)
        try { withContext(Dispatchers.IO) { c.resumeUploads() } } catch (_: Exception) {}
        Outbox.flush(model)
    }

    /** Poll `pendingUploads()` about once a second for as long as anything is on its way. */
    fun watch(model: AppModel) {
        if (poller?.isActive == true) return
        poller = model.launchJob {
            var idle = 0
            while (idle < 3) {
                val c = model.client
                val rows = try { c?.pendingUploads() } catch (_: Exception) { null }
                    ?.map { UploadRules.Row(it.uploadId, it.sent.toLong(), it.total.toLong(), it.done) } ?: emptyList()
                val next = rows.associateBy { it.uploadId }
                if (next != progress) progress = next
                // A few quiet rounds before stopping: a just-queued upload shows up a beat later.
                idle = if (UploadRules.anyPending(rows)) 0 else idle + 1
                // Nobody is looking at a progress bar in the background (an upload queued
                // offline can stay pending for hours): look far less often there.
                delay(if (model.appForeground) 1000 else 15_000)
            }
            if (progress.isNotEmpty()) progress = emptyMap()
        }
    }

    private const val MAX_PHOTO_BYTES = 64L * 1024 * 1024

    /** Copy a stream to a file, never past [cap] bytes; nothing partial is left behind. */
    private fun copyBounded(input: java.io.InputStream, dest: File, cap: Long) {
        try { dest.outputStream().use { out -> AttachmentLimits.copyBounded(input, out, cap) } }
        catch (e: Exception) { dest.delete(); throw e }
    }

    private fun queryName(ctx: Context, uri: Uri): String? = try {
        ctx.contentResolver.query(uri, null, null, null, null)?.use { c ->
            val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
        }
    } catch (_: Exception) { null }
}
