package io.skwod.app

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.ColorMatrix
import android.graphics.ColorMatrixColorFilter
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.positionChanged
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import kotlin.math.roundToInt

// MARK: model

/** One draggable/resizable/rotatable text layer (Instagram-style). Unit coords survive resizes. */
data class EditorText(
    val id: Long = System.nanoTime(),
    var text: String = "",
    var colorIndex: Int = 0,
    var styleIndex: Int = 0,
    var pill: Boolean = false,
    var unitX: Float = 0.5f,
    var unitY: Float = 0.5f,
    var scale: Float = 1f,
    var rotation: Float = 0f,
)

val editorPalette = listOf(
    Color.White, Color.Black, Color(0xFFFF4545), Color(0xFFFF9500), Color(0xFFFFD60A),
    Color(0xFF4DD964), Color(0xFF32D0DE), Color(0xFF5A8CFF), Color(0xFFAF52DE), Color(0xFFFF2D92),
)
private val paletteNeedsDarkText = listOf(true, false, false, true, true, true, true, false, false, false)

/** Instagram-ish text styles: label + Compose font + the Paint typeface used at flatten time. */
private data class EditorStyle(val label: String, val family: FontFamily, val typeface: Typeface)
private val editorStyles = listOf(
    EditorStyle("Classic", FontFamily.SansSerif, Typeface.create(Typeface.SANS_SERIF, Typeface.BOLD)),
    EditorStyle("Modern", FontFamily.SansSerif, Typeface.create("sans-serif-black", Typeface.NORMAL)),
    EditorStyle("Type", FontFamily.Monospace, Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)),
    EditorStyle("Serif", FontFamily.Serif, Typeface.create(Typeface.SERIF, Typeface.BOLD)),
)

/** Photo filter presets as ColorMatrix transforms (applied live and at flatten time). */
private data class EditorFilter(val name: String, val matrix: ColorMatrix?)
private val editorFilters = listOf(
    EditorFilter("Normal", null),
    EditorFilter("Vivid", ColorMatrix().apply { setSaturation(1.35f) }),
    EditorFilter("Warm", ColorMatrix(floatArrayOf(
        1.12f, 0f, 0f, 0f, 12f, 0f, 1.02f, 0f, 0f, 4f, 0f, 0f, 0.88f, 0f, 0f, 0f, 0f, 0f, 1f, 0f))),
    EditorFilter("Cool", ColorMatrix(floatArrayOf(
        0.9f, 0f, 0f, 0f, 0f, 0f, 1.0f, 0f, 0f, 4f, 0f, 0f, 1.14f, 0f, 12f, 0f, 0f, 0f, 1f, 0f))),
    EditorFilter("Fade", ColorMatrix().apply {
        setSaturation(0.72f)
        postConcat(ColorMatrix(floatArrayOf(
            0.9f, 0f, 0f, 0f, 24f, 0f, 0.9f, 0f, 0f, 24f, 0f, 0f, 0.9f, 0f, 24f, 0f, 0f, 0f, 1f, 0f)))
    }),
    EditorFilter("Retro", ColorMatrix(floatArrayOf(
        1.0f, 0.1f, 0f, 0f, 16f, 0.05f, 0.95f, 0f, 0f, 10f, 0f, 0.1f, 0.82f, 0f, 6f, 0f, 0f, 0f, 1f, 0f))),
    EditorFilter("Mono", ColorMatrix().apply { setSaturation(0f) }),
    EditorFilter("Noir", ColorMatrix().apply {
        setSaturation(0f)
        postConcat(ColorMatrix(floatArrayOf(
            1.3f, 0f, 0f, 0f, -24f, 0f, 1.3f, 0f, 0f, -24f, 0f, 0f, 1.3f, 0f, -24f, 0f, 0f, 0f, 1f, 0f)))
    }),
)

// MARK: editor

/**
 * The Instagram-style full-screen story/post editor: pick a photo, tap-through filters, add text
 * layers you can drag / pinch-resize / rotate / recolor (pill background, font styles), attach a
 * song hook — then everything is flattened into ONE bitmap and handed back, so every existing
 * viewer renders it as a plain photo. `square` = post (1:1); otherwise story (9:16).
 */
@Composable
fun StoryEditorScreen(
    square: Boolean = false,
    initialImage: ByteArray? = null,
    onClose: () -> Unit,
    /** The flattened picture, and (stories) the song picked and which part of it plays. */
    onDone: (ByteArray?, MusicTrack?, MusicClip?) -> Unit,
) {
    val ctx = LocalContext.current
    val density = androidx.compose.ui.platform.LocalDensity.current
    val scope = rememberCoroutineScope()
    var imageBytes by remember { mutableStateOf(initialImage) }
    var filterIndex by remember { mutableStateOf(0) }
    var overlays by remember { mutableStateOf(listOf<EditorText>()) }
    var editing by remember { mutableStateOf<EditorText?>(null) }
    var showFilters by remember { mutableStateOf(false) }
    var canvasW by remember { mutableStateOf(1) }
    var canvasH by remember { mutableStateOf(1) }
    var sharing by remember { mutableStateOf(false) }
    /** Stories: a song, and which part of its preview plays. */
    var song by remember { mutableStateOf<MusicTrack?>(null) }
    var clip by remember { mutableStateOf(MusicClip.FALLBACK) }
    var showMusic by remember { mutableStateOf(false) }
    if (showMusic) MusicSearchDialog(onPick = { song = it; clip = MusicClip.FALLBACK; showMusic = false }, onClose = { showMusic = false })
    /// id of the layer being dragged (shows the trash can) + whether it's hovering the can.
    var draggingId by remember { mutableStateOf<Long?>(null) }
    var hoverTrash by remember { mutableStateOf(false) }

    // Decode + filter off the main thread — a 12MP decode/filter in composition froze the UI.
    val baseBitmap by produceState<Bitmap?>(null, imageBytes) {
        val bytes = imageBytes
        value = if (bytes == null) null else withContext(Dispatchers.Default) {
            SafeImage.decode(bytes)
        }
    }
    // (bitmap, filterIndex-it-was-rendered-with): keeps the previous frame while a new filter
    // renders (no flash), while letting the share path detect a stale/in-flight preview.
    var filteredState by remember { mutableStateOf<Pair<Bitmap, Int>?>(null) }
    LaunchedEffect(baseBitmap, filterIndex) {
        val base = baseBitmap
        if (base == null) { filteredState = null; return@LaunchedEffect }
        val fi = filterIndex
        val bmp = withContext(Dispatchers.Default) { applyFilter(base, editorFilters[fi].matrix) }
        if (fi == filterIndex) filteredState = bmp to fi
    }
    val filtered = filteredState?.first

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) scope.launch {
            imageBytes = withContext(Dispatchers.IO) { ctx.contentResolver.openInputStream(uri)?.use { it.readBytes() } }
            filterIndex = 0
        }
    }

    val aspect = if (square) 1f else 9f / 16f

    Box(Modifier.fillMaxSize().background(Color.Black)) {
        // Canvas (aspect-fitted, centered).
        Box(Modifier.fillMaxSize().padding(horizontal = 12.dp, vertical = 64.dp), contentAlignment = Alignment.Center) {
            Box(
                Modifier.aspectRatio(aspect).fillMaxSize()
                    .clip(RoundedCornerShape(18.dp))
                    .onSizeChanged { canvasW = it.width; canvasH = it.height }
            ) {
                if (filtered != null) {
                    Image(filtered.asImageBitmap(), "photo", Modifier.fillMaxSize(), contentScale = ContentScale.Crop)
                } else {
                    Box(Modifier.fillMaxSize().background(
                        androidx.compose.ui.graphics.Brush.linearGradient(
                            listOf(Color(0xFF292B52), Color(0xFF573370)))),
                        contentAlignment = Alignment.Center) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally,
                            modifier = Modifier.clip(RoundedCornerShape(18.dp))
                                .background(Color.White.copy(alpha = 0.12f))
                                .clickable { picker.launch("image/*") }.padding(24.dp)) {
                            Icon(Icons.Filled.AddPhotoAlternate, null, tint = Color.White, modifier = Modifier.size(44.dp))
                            Text("Add a photo", color = Color.White.copy(alpha = 0.85f), fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
                overlays.forEach { layer ->
                    key(layer.id) {
                        EditorTextLayer(
                            layer = layer,
                            canvasW = canvasW, canvasH = canvasH,
                            dimmed = draggingId == layer.id && hoverTrash,
                            onChange = { changed ->
                                overlays = overlays.map { if (it.id == changed.id) changed else it }
                                hoverTrash = inTrashZone(changed.unitX, changed.unitY)
                            },
                            onDragState = { dragging ->
                                if (dragging) { draggingId = layer.id }
                                else {
                                    // Drop: on the trash can → delete (Instagram's drag-to-delete).
                                    val current = overlays.firstOrNull { it.id == layer.id }
                                    if (hoverTrash && current != null) overlays = overlays.filter { it.id != layer.id }
                                    draggingId = null; hoverTrash = false
                                }
                            },
                            onTap = { editing = layer }
                        )
                    }
                }
                // Instagram's drag-to-delete target: trash can at the bottom while dragging.
                if (draggingId != null) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.BottomCenter) {
                        Box(Modifier.padding(bottom = 16.dp)
                            .size(if (hoverTrash) 58.dp else 46.dp)
                            .clip(CircleShape)
                            .background(if (hoverTrash) Color(0xFFE53935) else Color.Black.copy(alpha = 0.5f)),
                            contentAlignment = Alignment.Center) {
                            Icon(Icons.Filled.Delete, "Delete", tint = Color.White,
                                modifier = Modifier.size(if (hoverTrash) 26.dp else 20.dp))
                        }
                    }
                }
            }
        }

        // Top chrome.
        Row(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically) {
            ChromeIcon(Icons.Filled.Close, "Close") { onClose() }
            Spacer(Modifier.weight(1f))
            if (imageBytes != null) {
                ChromeIcon(Icons.Filled.Image, "Change photo") { picker.launch("image/*") }
                Spacer(Modifier.width(12.dp))
                ChromeIcon(Icons.Filled.AutoFixHigh, "Filters") { showFilters = !showFilters }
                Spacer(Modifier.width(12.dp))
            }
            Box(Modifier.size(38.dp).clip(CircleShape).background(Color.Black.copy(alpha = 0.45f))
                .clickable {
                    val layer = EditorText(unitY = 0.4f + (overlays.size % 4) * 0.08f)
                    overlays = overlays + layer
                    editing = layer
                }, contentAlignment = Alignment.Center) {
                Text("Aa", color = Color.White, fontWeight = FontWeight.Black)
            }
            if (!square) {
                Spacer(Modifier.width(12.dp))
                ChromeIcon(Icons.Filled.MusicNote, if (song == null) "Add a song" else "Change the song") { showMusic = true }
            }
        }

        // Bottom chrome: filter strip + share.
        Column(Modifier.align(Alignment.BottomCenter).fillMaxWidth()) {
            val base = baseBitmap
            if (showFilters && base != null) {
                Row(Modifier.fillMaxWidth().background(Color.Black.copy(alpha = 0.35f))
                    .horizontalScroll(rememberScrollState()).padding(horizontal = 14.dp, vertical = 8.dp)) {
                    val thumb = remember(base) { Bitmap.createScaledBitmap(base, 112, 112, true) }
                    editorFilters.forEachIndexed { i, f ->
                        val preview = remember(thumb, i) { applyFilter(thumb, f.matrix) }
                        Column(horizontalAlignment = Alignment.CenterHorizontally,
                            modifier = Modifier.padding(end = 12.dp).clickable { filterIndex = i }) {
                            Image(preview.asImageBitmap(), f.name,
                                Modifier.size(56.dp).clip(RoundedCornerShape(12.dp))
                                    .border(2.dp, if (filterIndex == i) Color.White else Color.White.copy(alpha = 0.15f),
                                        RoundedCornerShape(12.dp)),
                                contentScale = ContentScale.Crop)
                            Text(f.name, color = if (filterIndex == i) Color.White else Color.White.copy(alpha = 0.6f),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = if (filterIndex == i) FontWeight.Bold else FontWeight.Normal)
                        }
                    }
                }
            }
            // Instagram's "pick the part": the strip, a length, and it plays as you choose.
            song?.takeIf { !square && !sharing }?.let { s ->
                key(s.id, s.previewUrl) {
                    MusicClipTrimmer(s, clip, onClip = { clip = it }, onRemove = { song = null },
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp))
                }
            }
            Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 14.dp)) {
                Spacer(Modifier.weight(1f))
                Button(
                    onClick = {
                        if (sharing) return@Button
                        sharing = true
                        // 30.sp on the live canvas → the same fraction of the flattened width.
                        val textPxOnCanvas = with(density) { 30.sp.toPx() }
                        val dpPx = with(density) { 1.dp.toPx() }
                        val bytes = imageBytes
                        val fi = filterIndex
                        // Only trust the preview if it was rendered with the CURRENT filter.
                        val ready = filteredState?.takeIf { it.second == fi }?.first
                        scope.launch {
                            val out = withContext(Dispatchers.Default) {
                                // Never publish without the chosen photo: if the async preview
                                // hasn't landed yet (or is stale), decode + filter right here.
                                val photo = ready ?: bytes?.let {
                                    SafeImage.decode(it)?.let { b -> applyFilter(b, editorFilters[fi].matrix) }
                                }
                                flatten(photo, overlays, square, textPxOnCanvas, canvasW, dpPx)
                            }
                            onDone(out, song.takeIf { !square }, clip.takeIf { song != null && !square })
                        }
                    },
                    enabled = !sharing && (imageBytes != null || overlays.isNotEmpty() || (song != null && !square)),
                    colors = ButtonDefaults.buttonColors(containerColor = Color.White, contentColor = Color.Black)
                ) {
                    Text(if (sharing) "…" else if (square) "Done" else "Share story", fontWeight = FontWeight.Bold)
                    Spacer(Modifier.width(6.dp))
                    Icon(Icons.Filled.ArrowForward, null, Modifier.size(16.dp))
                }
            }
        }

        editing?.let { layer ->
            TextLayerDialog(
                layer = layer,
                onDone = { edited ->
                    val trimmed = edited.copy(text = edited.text.trim())
                    overlays = if (trimmed.text.isEmpty()) overlays.filter { it.id != layer.id }
                               else overlays.map { if (it.id == layer.id) trimmed else it }
                    editing = null
                },
                onDelete = { overlays = overlays.filter { it.id != layer.id }; editing = null }
            )
        }
    }
}

@Composable
private fun ChromeIcon(icon: androidx.compose.ui.graphics.vector.ImageVector, desc: String, onClick: () -> Unit) {
    Box(Modifier.size(38.dp).clip(CircleShape).background(Color.Black.copy(alpha = 0.45f)).clickable(onClick = onClick),
        contentAlignment = Alignment.Center) {
        Icon(icon, desc, tint = Color.White, modifier = Modifier.size(19.dp))
    }
}

/** The drop-to-delete region: the bottom-center strip of the canvas where the trash can sits. */
private fun inTrashZone(unitX: Float, unitY: Float): Boolean =
    kotlin.math.abs(unitX - 0.5f) < 0.18f && unitY > 0.86f

/** One live text layer: drag + pinch + rotate via transform gestures; tap to edit. */
@Composable
private fun EditorTextLayer(
    layer: EditorText,
    canvasW: Int,
    canvasH: Int,
    dimmed: Boolean = false,
    onChange: (EditorText) -> Unit,
    onDragState: (Boolean) -> Unit = {},
    onTap: () -> Unit,
) {
    val style = editorStyles[layer.styleIndex % editorStyles.size]
    val color = editorPalette[layer.colorIndex % editorPalette.size]
    val fg = if (layer.pill) (if (paletteNeedsDarkText[layer.colorIndex % editorPalette.size]) Color.Black else Color.White) else color
    var selfW by remember { mutableStateOf(0) }
    var selfH by remember { mutableStateOf(0) }
    // The gesture coroutine (pointerInput) outlives recompositions; read the LATEST layer through
    // this holder — capturing `layer` directly froze every gesture at its composition-time value.
    val current by rememberUpdatedState(layer)
    val curW by rememberUpdatedState(canvasW)
    val curH by rememberUpdatedState(canvasH)

    Box(
        Modifier
            // offset() places our top-left; subtract half the measured size to center on the point.
            .offset {
                IntOffset(
                    (current.unitX * curW - selfW / 2f).roundToInt(),
                    (current.unitY * curH - selfH / 2f).roundToInt()
                )
            }
            .onSizeChanged { selfW = it.width; selfH = it.height }
            .scale(layer.scale)
            .rotate(layer.rotation)
            .pointerInput(layer.id) {
                // Report drag start/end (shows/hides the trash can and commits drop-to-delete).
                awaitEachGesture {
                    awaitFirstDown(requireUnconsumed = false)
                    var moved = false
                    do {
                        val event = awaitPointerEvent()
                        if (!moved && event.changes.any { it.positionChanged() }) {
                            moved = true
                            onDragState(true)
                        }
                    } while (event.changes.any { it.pressed })
                    if (moved) onDragState(false)
                }
            }
            .pointerInput(layer.id) {
                detectTransformGestures { _, pan, zoom, rot ->
                    val l = current
                    // pan arrives in the layer's rotated + inverse-scaled local frame (the gesture
                    // sits after .scale/.rotate) — map it back to canvas space before applying.
                    val rad = Math.toRadians(l.rotation.toDouble())
                    val cosR = kotlin.math.cos(rad).toFloat()
                    val sinR = kotlin.math.sin(rad).toFloat()
                    val dx = (pan.x * cosR - pan.y * sinR) * l.scale
                    val dy = (pan.x * sinR + pan.y * cosR) * l.scale
                    onChange(l.copy(
                        unitX = (l.unitX + dx / curW).coerceIn(0.03f, 0.97f),
                        unitY = (l.unitY + dy / curH).coerceIn(0.03f, 0.97f),
                        scale = (l.scale * zoom).coerceIn(0.4f, 6f),
                        rotation = l.rotation + rot,
                    ))
                }
            }
            .clickable(onClick = onTap)
            .then(
                if (layer.pill) Modifier.clip(RoundedCornerShape(12.dp)).background(color).padding(horizontal = 14.dp, vertical = 8.dp)
                else Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
            )
            .alpha(if (dimmed) 0.5f else 1f)
    ) {
        Text(layer.text, color = fg, fontSize = 30.sp, textAlign = TextAlign.Center,
            fontFamily = style.family, fontWeight = FontWeight.Bold)
    }
}

/** Full-screen text edit dialog: field + font styles + pill toggle + color swatches. */
@Composable
private fun TextLayerDialog(layer: EditorText, onDone: (EditorText) -> Unit, onDelete: () -> Unit) {
    var draft by remember { mutableStateOf(layer) }
    val color = editorPalette[draft.colorIndex % editorPalette.size]
    val fg = if (draft.pill) (if (paletteNeedsDarkText[draft.colorIndex % editorPalette.size]) Color.Black else Color.White) else color

    Dialog(onDismissRequest = { onDone(draft) },
        properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.72f))
            .clickable { onDone(draft) }) {
            Column(Modifier.fillMaxSize().padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Row(Modifier.fillMaxWidth()) {
                    TextButton(onClick = onDelete) { Text("Delete", color = Color(0xFFF87171)) }
                    Spacer(Modifier.weight(1f))
                    TextButton(onClick = { onDone(draft) }) { Text("Done", color = Color.White, fontWeight = FontWeight.Bold) }
                }
                Spacer(Modifier.weight(1f))
                OutlinedTextField(
                    draft.text, { draft = draft.copy(text = it) },
                    placeholder = { Text("Type something…", color = Color.White.copy(alpha = 0.5f)) },
                    textStyle = TextStyle(color = fg, fontSize = 28.sp, textAlign = TextAlign.Center,
                        fontFamily = editorStyles[draft.styleIndex % editorStyles.size].family,
                        fontWeight = FontWeight.Bold),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = if (draft.pill) color else Color.Transparent,
                        unfocusedContainerColor = if (draft.pill) color else Color.Transparent,
                        focusedBorderColor = Color.Transparent, unfocusedBorderColor = Color.Transparent),
                    modifier = Modifier.fillMaxWidth(0.85f)
                )
                Spacer(Modifier.weight(1f))
                // Font styles + pill toggle.
                Row(verticalAlignment = Alignment.CenterVertically) {
                    editorStyles.forEachIndexed { i, s ->
                        val sel = draft.styleIndex == i
                        Text(s.label, color = if (sel) Color.Black else Color.White,
                            fontFamily = s.family, fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.labelMedium,
                            modifier = Modifier.padding(end = 8.dp).clip(RoundedCornerShape(50))
                                .background(if (sel) Color.White else Color.White.copy(alpha = 0.15f))
                                .clickable { draft = draft.copy(styleIndex = i) }
                                .padding(horizontal = 12.dp, vertical = 7.dp))
                    }
                    Icon(if (draft.pill) Icons.Filled.FormatColorFill else Icons.Filled.FormatColorText,
                        "Pill background", tint = Color.White,
                        modifier = Modifier.size(30.dp).clickable { draft = draft.copy(pill = !draft.pill) })
                }
                Spacer(Modifier.height(14.dp))
                // Color swatches.
                Row(Modifier.horizontalScroll(rememberScrollState()).padding(bottom = 20.dp)) {
                    editorPalette.forEachIndexed { i, c ->
                        Box(Modifier.padding(end = 10.dp).size(30.dp).clip(CircleShape).background(c)
                            .border(if (draft.colorIndex == i) 3.dp else 1.dp, Color.White, CircleShape)
                            .clickable { draft = draft.copy(colorIndex = i) })
                    }
                }
            }
        }
    }
}

// MARK: bitmap ops

private fun applyFilter(src: Bitmap, matrix: ColorMatrix?): Bitmap {
    if (matrix == null) return src
    val out = Bitmap.createBitmap(src.width, src.height, Bitmap.Config.ARGB_8888)
    val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply { colorFilter = ColorMatrixColorFilter(matrix) }
    Canvas(out).drawBitmap(src, 0f, 0f, paint)
    return out
}

/** Flatten the canvas — filtered photo (center-cropped) + text layers — into one JPEG.
 *  `textPxOnCanvas`/`canvasPxW` describe how 30.sp text actually measured on the LIVE canvas, so
 *  the render keeps the exact text-to-canvas proportion the user laid out (WYSIWYG). */
private fun flatten(photo: Bitmap?, overlays: List<EditorText>, square: Boolean,
                    textPxOnCanvas: Float, canvasPxW: Int, dpPx: Float): ByteArray? {
    if (photo == null && overlays.isEmpty()) return null
    val w = 1080
    val h = if (square) 1080 else 1920
    // Fraction of live-canvas width that 30.sp occupies → same fraction of the render width.
    val textFraction = if (canvasPxW > 0) textPxOnCanvas / canvasPxW else 30f / 360f
    val uiToRender = if (canvasPxW > 0) w.toFloat() / canvasPxW else 3f
    val out = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
    val canvas = Canvas(out)

    if (photo != null) {
        // Center-crop the photo to fill (matches ContentScale.Crop in the live canvas).
        val scale = maxOf(w.toFloat() / photo.width, h.toFloat() / photo.height)
        val dw = photo.width * scale; val dh = photo.height * scale
        val left = (w - dw) / 2f; val top = (h - dh) / 2f
        canvas.drawBitmap(photo, null, RectF(left, top, left + dw, top + dh), Paint(Paint.FILTER_BITMAP_FLAG))
    } else {
        // The gradient placeholder background.
        val paint = Paint().apply {
            shader = android.graphics.LinearGradient(0f, 0f, w.toFloat(), h.toFloat(),
                0xFF292B52.toInt(), 0xFF573370.toInt(), android.graphics.Shader.TileMode.CLAMP)
        }
        canvas.drawRect(0f, 0f, w.toFloat(), h.toFloat(), paint)
    }

    val baseTextPx = w * textFraction
    for (layer in overlays) {
        val style = editorStyles[layer.styleIndex % editorStyles.size]
        val colorInt = editorPalette[layer.colorIndex % editorPalette.size].let {
            android.graphics.Color.argb((it.alpha * 255).toInt(), (it.red * 255).toInt(),
                (it.green * 255).toInt(), (it.blue * 255).toInt())
        }
        val dark = paletteNeedsDarkText[layer.colorIndex % editorPalette.size]
        val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            textSize = baseTextPx * layer.scale
            typeface = style.typeface
            textAlign = Paint.Align.CENTER
            color = if (layer.pill) (if (dark) android.graphics.Color.BLACK else android.graphics.Color.WHITE) else colorInt
            if (!layer.pill) setShadowLayer(4f, 0f, 2f, android.graphics.Color.argb(115, 0, 0, 0))
        }
        val cx = layer.unitX * w
        val cy = layer.unitY * h
        canvas.save()
        canvas.rotate(layer.rotation, cx, cy)
        val lines = layer.text.split("\n")
        val lineH = textPaint.fontSpacing
        val totalH = lineH * lines.size
        if (layer.pill) {
            val maxLineW = lines.maxOf { textPaint.measureText(it) }
            // 14dp/8dp padding on the live canvas, mapped through the same canvas→render scale.
            val padX = 14f * dpPx * layer.scale * uiToRender
            val padY = 8f * dpPx * layer.scale * uiToRender
            val pillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = colorInt }
            canvas.drawRoundRect(
                RectF(cx - maxLineW / 2 - padX, cy - totalH / 2 - padY, cx + maxLineW / 2 + padX, cy + totalH / 2 + padY),
                24f * layer.scale, 24f * layer.scale, pillPaint)
        }
        lines.forEachIndexed { i, line ->
            val y = cy - totalH / 2 + lineH * i - textPaint.ascent() - (lineH + textPaint.ascent() + textPaint.descent()) / 2
            canvas.drawText(line, cx, y, textPaint)
        }
        canvas.restore()
    }

    val stream = ByteArrayOutputStream()
    out.compress(Bitmap.CompressFormat.JPEG, 88, stream)
    return stream.toByteArray()
}
