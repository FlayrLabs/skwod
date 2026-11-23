package io.skwod.app

import android.content.Intent
import android.media.MediaPlayer
import android.net.Uri
import android.util.Base64
import android.widget.VideoView
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/** Renders a decoded message body: any attachment/music card, then the text. Shared by all bubbles. */
@Composable
fun MessageBody(body: String) {
    val parsed = remember(body) { ChatTags.parse(body) }
    Column {
        parsed.attachment?.let { AttachmentContent(it); if (parsed.text.isNotBlank()) Spacer(Modifier.height(6.dp)) }
        parsed.music?.let { MusicContent(it); if (parsed.text.isNotBlank()) Spacer(Modifier.height(6.dp)) }
        if (parsed.text.isNotBlank() || (parsed.attachment == null && parsed.music == null)) {
            MarkdownOrEmoji(parsed.text, parsed.mentions.mentions)
        }
    }
}

@Composable
private fun AttachmentContent(a: ChatAttachment) {
    // My own attachment that is still on its way: the descriptor names the core's placeholder,
    // not a blob — there is nothing to download yet, only progress to show.
    if (UploadRules.uploadId(a.blobId) != null) { UploadingAttachment(a); return }
    when (a.kind) {
        "image" -> ImageAttachment(a)
        "video" -> VideoAttachment(a)
        "audio" -> AudioAttachment(a)
        else -> FileAttachment(a)
    }
}

/** "Uploading… 1.2 MB/8.4 MB" with a bar, from the core's `pendingUploads()` (polled about once a second). */
@Composable
private fun UploadingAttachment(a: ChatAttachment) {
    val row = UploadRules.progressFor(a.blobId, Uploads.progress.values)
    Surface(color = Color.White.copy(alpha = 0.05f), shape = RoundedCornerShape(14.dp), modifier = Modifier.widthIn(max = 300.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text(a.name, color = Color.White, maxLines = 1, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(6.dp))
            if (row != null) {
                LinearProgressIndicator(progress = { UploadRules.fraction(row) }, modifier = Modifier.fillMaxWidth(), color = SkAccent)
                Spacer(Modifier.height(4.dp))
                Text(UploadRules.line(row, AttachmentService::formattedSize), color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
            } else {
                // Not started yet (offline, or queued behind another send).
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = SkAccent)
                Spacer(Modifier.height(4.dp))
                Text("Waiting to upload · ${AttachmentService.formattedSize(a.size)}", color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

/** A shared download/decrypt loader for the attachment views. */
@Composable
private fun rememberLoader(): AttachLoaderState = remember { AttachLoaderState() }

private class AttachLoaderState {
    var localFile by mutableStateOf<File?>(null)
    var busy by mutableStateOf(false)
    var error by mutableStateOf<String?>(null)
}

@Composable
private fun ImageAttachment(a: ChatAttachment) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val loader = rememberLoader()
    var showFull by remember { mutableStateOf(false) }
    val thumb = remember(a.blobId) {
        a.thumbB64?.let { b64 ->
            decodeThumb(b64)
        }
    }
    if (thumb != null) {
        Box(Modifier.clip(RoundedCornerShape(12.dp)).clickable {
            showFull = true
            scope.launch { fetch(ctx, a, loader) }
        }) {
            Image(thumb.asImageBitmap(), a.name, Modifier.sizeIn(maxWidth = 260.dp, maxHeight = 260.dp), contentScale = ContentScale.Fit)
        }
    } else {
        FileAttachment(a)
    }
    if (showFull) {
        Dialog(onDismissRequest = { showFull = false }) {
            Surface(color = Color.Black, shape = RoundedCornerShape(16.dp)) {
                Box(Modifier.fillMaxWidth().heightIn(min = 240.dp), contentAlignment = Alignment.Center) {
                    val full = loader.localFile
                    when {
                        full != null -> {
                            val bmp = remember(full) { SafeImage.decodeInboundFile(full) }
                            if (bmp != null) Image(bmp.asImageBitmap(), a.name, Modifier.fillMaxWidth(), contentScale = ContentScale.Fit)
                            else Text("This image can't be shown safely (it is not a picture, or claims an impossible size).",
                                color = Color(0xFFFFA726), modifier = Modifier.padding(24.dp))
                        }
                        loader.error != null -> Text(loader.error!!, color = Color(0xFFFFA726), modifier = Modifier.padding(24.dp))
                        else -> CircularProgressIndicator(color = Color.White)
                    }
                }
            }
        }
    }
}

@Composable
private fun VideoAttachment(a: ChatAttachment) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val loader = rememberLoader()
    var playing by remember { mutableStateOf(false) }
    val poster = remember(a.blobId) {
        a.thumbB64?.let { b64 ->
            decodeThumb(b64)
        }
    }
    Box(Modifier.size(300.dp, 200.dp).clip(RoundedCornerShape(12.dp)).background(Color.White.copy(alpha = 0.06f)),
        contentAlignment = Alignment.Center) {
        val file = loader.localFile
        if (playing && file != null) {
            AndroidView(factory = { c ->
                VideoView(c).apply {
                    setVideoURI(Uri.fromFile(file)); setOnPreparedListener { it.start() }
                }
            }, modifier = Modifier.fillMaxSize())
        } else {
            if (poster != null) Image(poster.asImageBitmap(), a.name, Modifier.fillMaxSize(), contentScale = ContentScale.Crop)
            IconButton(onClick = { scope.launch { fetch(ctx, a, loader); if (loader.localFile != null) playing = true } }) {
                if (loader.busy) CircularProgressIndicator(color = Color.White)
                else Icon(Icons.Filled.PlayCircle, "Play", tint = Color.White.copy(alpha = 0.9f), modifier = Modifier.size(48.dp))
            }
        }
    }
    loader.error?.let { Text(it, color = Color(0xFFFFA726), style = MaterialTheme.typography.labelSmall) }
}

@Composable
private fun AudioAttachment(a: ChatAttachment) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val loader = rememberLoader()
    var player by remember { mutableStateOf<MediaPlayer?>(null) }
    var playing by remember { mutableStateOf(false) }
    DisposableEffect(Unit) { onDispose { player?.release() } }

    Surface(color = Color.White.copy(alpha = 0.05f), shape = RoundedCornerShape(14.dp), modifier = Modifier.widthIn(max = 300.dp)) {
        Row(Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = {
                if (playing) { player?.pause(); playing = false; return@IconButton }
                scope.launch {
                    fetch(ctx, a, loader)
                    loader.localFile?.let { f ->
                        if (player == null) player = MediaPlayer().apply {
                            setDataSource(f.absolutePath); prepare(); setOnCompletionListener { playing = false }
                        }
                        player?.start(); playing = true
                    }
                }
            }) {
                if (loader.busy) CircularProgressIndicator(color = SkAccent, modifier = Modifier.size(24.dp))
                else Icon(if (playing) Icons.Filled.PauseCircle else Icons.Filled.PlayCircle, "Play/pause",
                    tint = SkAccent, modifier = Modifier.size(32.dp))
            }
            // Embedded cover art, if the file carried any.
            val art = remember(a.blobId) {
                a.thumbB64?.let { b64 ->
                    decodeThumb(b64)
                }
            }
            if (art != null) {
                Spacer(Modifier.width(8.dp))
                Image(art.asImageBitmap(), a.name, Modifier.size(40.dp).clip(RoundedCornerShape(8.dp)),
                    contentScale = ContentScale.Crop)
            }
            Spacer(Modifier.width(8.dp))
            Column {
                Text(a.name, color = Color.White, maxLines = 1, style = MaterialTheme.typography.bodyMedium)
                Text(AttachmentService.formattedSize(a.size), color = Color.White.copy(alpha = 0.5f),
                    style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

@Composable
private fun FileAttachment(a: ChatAttachment) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val loader = rememberLoader()
    Surface(color = Color.White.copy(alpha = 0.05f), shape = RoundedCornerShape(14.dp), modifier = Modifier.widthIn(max = 300.dp)) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.InsertDriveFile, null, tint = SkAccent.copy(alpha = 0.8f), modifier = Modifier.size(26.dp))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(a.name, color = Color.White, maxLines = 1, style = MaterialTheme.typography.bodyMedium)
                Text(AttachmentService.formattedSize(a.size), color = Color.White.copy(alpha = 0.5f),
                    style = MaterialTheme.typography.labelSmall)
                if (remember(a.name, a.mime) { AttachmentOpenPolicy.isInstallable(a.name, a.mime) }) {
                    Text("App package — Skwod won't open or install it.", color = Color(0xFFFFA726), style = MaterialTheme.typography.labelSmall)
                }
                loader.error?.let { Text(it, color = Color(0xFFFFA726), style = MaterialTheme.typography.labelSmall) }
            }
            Spacer(Modifier.width(8.dp))
            if (loader.busy) {
                CircularProgressIndicator(color = SkAccent, modifier = Modifier.size(22.dp))
            } else if (loader.localFile != null) {
                val file = loader.localFile!!
                // An app package (or anything else the system would install or run) is never
                // opened from here — it can only be saved / passed on as a file.
                val openable = remember(file) { viewMime(file, a) != null }
                if (openable) {
                    IconButton(onClick = { openFile(ctx, file, a) }) {
                        Icon(Icons.Filled.OpenInNew, "Open", tint = Color.White.copy(alpha = 0.75f))
                    }
                }
                IconButton(onClick = { shareFile(ctx, file) }) {
                    Icon(Icons.Filled.Share, "Save or share", tint = Color.White.copy(alpha = 0.75f))
                }
            } else {
                IconButton(onClick = { scope.launch { fetch(ctx, a, loader) } }) {
                    Icon(Icons.Filled.Download, "Download", tint = SkAccent)
                }
            }
        }
    }
}

@Composable
internal fun MusicContent(t: MusicTrack) {
    val ctx = LocalContext.current
    val openUrl = t.safeUrl
    Surface(color = Color.White.copy(alpha = 0.05f), shape = RoundedCornerShape(14.dp), modifier = Modifier.widthIn(max = 300.dp)
        // The URL comes from the sender: it is offered only if it is on one of Apple's own
        // hosts (https, no credentials, default port) — the same allowlist as the Apple app.
        .then(openUrl?.let { url -> Modifier.clickable { runCatching { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) } } } ?: Modifier)
        ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.MusicNote, null, tint = Color(0xFFFA57A5), modifier = Modifier.size(26.dp))
            Spacer(Modifier.width(12.dp))
            Column {
                Text(t.title, color = Color.White, maxLines = 1, style = MaterialTheme.typography.bodyMedium)
                Text(t.artist.ifBlank { "Apple Music" }, color = Color.White.copy(alpha = 0.5f),
                    style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

private suspend fun fetch(ctx: android.content.Context, a: ChatAttachment, loader: AttachLoaderState) {
    if (loader.localFile != null || loader.busy) return
    val store = AppModel.get(ctx).blobStore()
    if (store == null) { loader.error = "Not signed in."; return }
    loader.busy = true
    try { loader.localFile = withContext(Dispatchers.IO) { AttachmentService.localFile(ctx, a, store) } }
    catch (e: Exception) { loader.error = (e as? AttachmentException)?.message ?: "Couldn't fetch the file." }
    finally { loader.busy = false }
}

/**
 * An embedded thumbnail is the sender's bytes: small by convention, but nothing enforces it.
 * Bounded like every other inbound image (see [SafeImage]); a thumbnail never needs more than
 * a megabyte or 1024 px.
 */
private fun decodeThumb(b64: String): android.graphics.Bitmap? = try {
    if (b64.length > 1_500_000) null
    else SafeImage.decodeInbound(Base64.decode(b64, Base64.DEFAULT), 1024)
} catch (_: Throwable) { null }

/** The first bytes of a decrypted file, for content sniffing. */
private fun head(file: File): ByteArray? = try {
    file.inputStream().use { input -> ByteArray(4096).let { buf -> val n = input.read(buf); if (n <= 0) null else buf.copyOf(n) } }
} catch (_: Exception) { null }

/** The type to open [file] with, or null when it may only be shared as a file (see [AttachmentOpenPolicy]). */
private fun viewMime(file: File, a: ChatAttachment): String? =
    AttachmentOpenPolicy.viewMime(file.name, a.mime, head(file)) { ext ->
        android.webkit.MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext)
    }

/**
 * Open a decrypted attachment in another app. Never for anything the system would install or
 * run: this app holds REQUEST_INSTALL_PACKAGES for its own verified update, so an `.apk` a
 * member sent, handed to ACTION_VIEW from here, would reach the package installer with this
 * app as its trusted source.
 */
private fun openFile(ctx: android.content.Context, file: File, a: ChatAttachment) {
    val mime = viewMime(file, a) ?: return
    try {
        val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.fileprovider", file)
        // The MIME comes from the file's own extension, NOT from the message-supplied
        // ChatAttachment.mime — that field is attacker-controllable.
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, mime)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        ctx.startActivity(intent)
    } catch (_: Exception) {}
}

/**
 * Hand a decrypted attachment to another app as an opaque file (save to Files, send on). The
 * type is always `application/octet-stream`, so no receiver is chosen for — or told — what the
 * sender claims it is; ACTION_SEND never reaches the package installer.
 */
private fun shareFile(ctx: android.content.Context, file: File) {
    try {
        val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.fileprovider", file)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_STREAM, uri)
            clipData = android.content.ClipData.newRawUri(file.name, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        ctx.startActivity(Intent.createChooser(send, "Save or share file").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    } catch (_: Exception) {}
}
