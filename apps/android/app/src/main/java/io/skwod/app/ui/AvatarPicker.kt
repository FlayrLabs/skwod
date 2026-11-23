package io.skwod.app

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PhotoLibrary
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * "Pick + preview + save" dialog for setting an avatar (profile pic, server icon, skwod icon).
 * The picked image is center-cropped, encrypted, and broadcast by `onPick` (AvatarStore handles the
 * E2EE + fan-out). `onRemove` (if given) clears it.
 */
@Composable
fun AvatarPickerDialog(
    title: String,
    currentKey: String?,
    name: String,
    onPick: suspend (ByteArray) -> Unit,
    onRemove: (suspend () -> Unit)? = null,
    onClose: () -> Unit,
) {
    val ctx = LocalContext.current
    val model = remember { AppModel.get(ctx) }
    val scope = rememberCoroutineScope()
    var picked by remember { mutableStateOf<ByteArray?>(null) }
    var busy by remember { mutableStateOf(false) }
    val pickedBmp = remember(picked) { picked?.let { SafeImage.decode(it, 1024) } }

    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) scope.launch {
            picked = withContext(Dispatchers.IO) { ctx.contentResolver.openInputStream(uri)?.use { it.readBytes() } }
        }
    }

    // Rendered as a full-screen overlay, NOT a Dialog — this picker is often opened from inside
    // another Dialog (the Profile screen), and a Dialog-inside-a-Dialog fails to show on Android.
    Box(
        Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.75f))
            .clickable(enabled = !busy) { onClose() },
        contentAlignment = Alignment.Center
    ) {
        Surface(color = GlassDialogTone, shape = RoundedCornerShape(20.dp),
            modifier = Modifier.padding(24.dp).clickable(enabled = false) {}) {
            Column(Modifier.padding(22.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Text(title, color = Color.White, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(18.dp))
                // Preview: newly picked, else current avatar, else monogram.
                if (pickedBmp != null) {
                    Image(pickedBmp.asImageBitmap(), "preview",
                        Modifier.size(140.dp).clip(RoundedCornerShape(70.dp)), contentScale = ContentScale.Crop)
                } else {
                    AvatarImage(currentKey, name, size = 140)
                }
                Spacer(Modifier.height(16.dp))
                Text("Square images look best — we'll center-crop and encrypt it. Only members who share a server with you can see it.",
                    color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall,
                    textAlign = TextAlign.Center)
                Spacer(Modifier.height(18.dp))
                Button(onClick = { launcher.launch("image/*") }, modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color.White.copy(alpha = 0.1f))) {
                    Icon(Icons.Filled.PhotoLibrary, null, tint = SkAccent); Spacer(Modifier.width(8.dp))
                    Text(if (picked == null) "Choose a photo" else "Choose a different photo", color = Color.White)
                }
                if (onRemove != null && currentKey != null && model.avatars.bitmap(currentKey) != null) {
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(onClick = {
                        busy = true
                        scope.launch { onRemove(); busy = false; onClose() }
                    }, modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFF87171))) {
                        Text("Remove current photo")
                    }
                }
                Spacer(Modifier.height(14.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = onClose, enabled = !busy) { Text("Cancel") }
                    Spacer(Modifier.width(8.dp))
                    Button(onClick = {
                        val p = picked ?: return@Button
                        busy = true
                        scope.launch { onPick(p); busy = false; onClose() }
                    }, enabled = picked != null && !busy) { Text(if (busy) "…" else "Save") }
                }
            }
        }
    }
}
