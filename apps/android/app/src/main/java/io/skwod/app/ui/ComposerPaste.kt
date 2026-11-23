package io.skwod.app

import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** A picture pasted into the composer, waiting for Send (or its ✕). Held in memory, bounded by [Uploads.readPastedImage]. */
class PastedImage(val bytes: ByteArray, val thumb: ImageBitmap?)

object ComposerPaste {
    private fun manager(ctx: Context) = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager

    /** The clipboard offers a picture. Reads only the description (no clip, no "pasted" toast). */
    fun hasImage(ctx: Context): Boolean = try {
        val d = manager(ctx)?.primaryClipDescription
        d != null && ClipboardImage.isImage((0 until d.mimeTypeCount).map { d.getMimeType(it) })
    } catch (_: Exception) { false }

    /** The content providers this app serves itself (a clip naming one of them is refused). */
    private fun ownAuthorities(ctx: Context): Set<String> = setOf("${ctx.packageName}.fileprovider") + try {
        ctx.packageManager.getPackageInfo(ctx.packageName, android.content.pm.PackageManager.GET_PROVIDERS)
            .providers.orEmpty().flatMap { it.authority.orEmpty().split(';') }.filter { it.isNotEmpty() }
    } catch (_: Exception) { emptyList() }

    /** Take the picture on the clipboard: bounded read, then a small preview. Throws [AttachmentException] with a sentence. */
    suspend fun take(ctx: Context, model: AppModel): PastedImage {
        val clip = try { manager(ctx)?.primaryClip } catch (_: Exception) { null }
        val uri = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.uri
            ?: throw AttachmentException("There's no picture on the clipboard.")
        if (!ClipboardImage.mayRead(uri.scheme, uri.authority, ownAuthorities(ctx)))
            throw AttachmentException("That picture can't be pasted. Save it, then attach it with + instead.")
        val bytes = Uploads.readPastedImage(ctx, model, uri)
        val thumb = withContext(Dispatchers.Default) {
            SafeImage.jpeg(bytes, 240, 70)?.let { android.graphics.BitmapFactory.decodeByteArray(it, 0, it.size)?.asImageBitmap() }
        } ?: throw AttachmentException("That isn't a picture Skwod can send.")
        return PastedImage(bytes, thumb)
    }
}

/** Whether the clipboard holds a picture right now, kept up to date while the composer is on screen. */
@Composable
fun rememberClipboardHasImage(): Boolean {
    val ctx = LocalContext.current
    var has by remember { mutableStateOf(ComposerPaste.hasImage(ctx)) }
    DisposableEffect(ctx) {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        val l = ClipboardManager.OnPrimaryClipChangedListener { has = ComposerPaste.hasImage(ctx) }
        try { cm?.addPrimaryClipChangedListener(l) } catch (_: Exception) {}
        onDispose { try { cm?.removePrimaryClipChangedListener(l) } catch (_: Exception) {} }
    }
    return has
}

/** "Paste image" — shown above the composer while the clipboard holds a picture. */
@Composable
fun PasteImageChip(onClick: () -> Unit) {
    Row(Modifier.padding(horizontal = 4.dp, vertical = 4.dp).clip(RoundedCornerShape(50))
        .background(Color.White.copy(alpha = 0.08f)).clickable(onClick = onClick)
        .padding(horizontal = 12.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(Icons.Filled.ContentPaste, null, tint = SkAccent, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(6.dp))
        Text("Paste image", color = Color.White.copy(alpha = 0.85f), fontSize = 13.sp)
    }
}

/** The pasted picture as it will be sent, with ✕ to remove it. */
@Composable
fun PastedImagePreview(p: PastedImage, onRemove: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        p.thumb?.let { Image(it, "Picture to send", Modifier.size(56.dp).clip(RoundedCornerShape(10.dp)), contentScale = ContentScale.Crop) }
        Spacer(Modifier.width(10.dp))
        Text("Picture · ${AttachmentService.formattedSize(p.bytes.size.toLong())} — sent with your message",
            color = Color.White.copy(alpha = 0.7f), fontSize = 12.sp, modifier = Modifier.weight(1f))
        IconButton(onClick = onRemove) { Icon(Icons.Filled.Close, "Remove picture", tint = Color.White.copy(alpha = 0.6f)) }
    }
}
