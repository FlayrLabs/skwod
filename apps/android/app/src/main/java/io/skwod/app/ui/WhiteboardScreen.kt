package io.skwod.app

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.UUID

// A working whiteboard: draw, pick colors, undo, clear. Realtime + E2EE when opened in a channel:
// strokes and clears sync over the same Sender-Key path as chat (see GameSync), with points
// normalized 0…1 so a phone and a Mac line up. Append-only + dedupe-by-id keeps it convergent.
val WHITEBOARD_PALETTE = listOf(
    SkAccent, Color.White, Color(0xFFA78BFA), Color(0xFFF472B6),
    Color(0xFF4ADE80), Color(0xFFFB923C), Color(0xFFFACC15)
)

// A stroke of normalized (0…1) points, so it renders identically at any canvas size.
data class NormStroke(val id: String, val points: List<Offset>, val colorIndex: Int, val width: Float)

@Composable
fun WhiteboardScreen(channelId: String? = null) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    val sync = remember(channelId) { channelId?.let { GameSync(model, it) } }

    val strokes = remember { mutableStateListOf<NormStroke>() }
    var current by remember { mutableStateOf<List<Offset>?>(null) }
    var colorIndex by remember { mutableStateOf(0) }
    val width = 8f
    var size by remember { mutableStateOf(IntSize.Zero) }
    val seen = remember { mutableStateListOf<String>() }
    var clearedBefore by remember { mutableStateOf(0L) }

    fun norm(o: Offset): Offset =
        Offset(if (size.width > 0) o.x / size.width else 0f, if (size.height > 0) o.y / size.height else 0f)
    fun denorm(o: Offset): Offset = Offset(o.x * size.width, o.y * size.height)

    // Merge remote strokes + clears while the board is open.
    LaunchedEffect(channelId) {
        val s = sync ?: return@LaunchedEffect
        s.watch {
            val events = s.fetchBoard()
            events.filter { it.event.kind == "clear" }.maxOfOrNull { it.createdAt }?.let { lastClear ->
                if (lastClear > clearedBefore) { clearedBefore = lastClear; strokes.clear(); seen.clear() }
            }
            for (m in events) {
                val e = m.event
                if (e.kind != "stroke") continue
                val sid = e.strokeId ?: continue
                if (m.createdAt <= clearedBefore || seen.contains(sid) || e.points == null) continue
                seen.add(sid)
                strokes.add(NormStroke(sid, e.points.map { Offset(it[0].toFloat(), it.getOrElse(1) { 0.0 }.toFloat()) },
                    e.colorIndex ?: 0, (e.width ?: 4.0).toFloat()))
            }
        }
    }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        ScreenTitle("Whiteboard", subtitle = if (channelId == null) "sketch together" else "live • encrypted")
        Spacer(Modifier.height(12.dp))
        Canvas(
            Modifier.weight(1f).fillMaxWidth().clip(RoundedCornerShape(20.dp))
                .background(Color.Black.copy(alpha = 0.25f))
                .onSizeChanged { size = it }
                .pointerInput(colorIndex, size) {
                    detectDragGestures(
                        onDragStart = { off -> current = listOf(norm(off)) },
                        onDrag = { change, _ -> change.consume(); current = (current ?: emptyList()) + norm(change.position) },
                        onDragEnd = {
                            current?.let { pts ->
                                if (pts.size > 1) {
                                    val id = UUID.randomUUID().toString()
                                    val stroke = NormStroke(id, pts, colorIndex, width)
                                    strokes.add(stroke); seen.add(id)
                                    sync?.let { s ->
                                        scope.launch {
                                            s.sendBoard(WhiteboardEvent("stroke", id,
                                                pts.map { listOf(it.x.toDouble(), it.y.toDouble()) }, colorIndex, width.toDouble()))
                                        }
                                    }
                                }
                            }
                            current = null
                        },
                        onDragCancel = { current = null }
                    )
                }
        ) {
            strokes.forEach { s -> drawStroke(s.points.map { denorm(it) }, WHITEBOARD_PALETTE[s.colorIndex.coerceIn(0, WHITEBOARD_PALETTE.size - 1)], s.width) }
            current?.let { pts -> drawStroke(pts.map { denorm(it) }, WHITEBOARD_PALETTE[colorIndex.coerceIn(0, WHITEBOARD_PALETTE.size - 1)], width) }
        }
        Spacer(Modifier.height(12.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            WHITEBOARD_PALETTE.forEachIndexed { i, c ->
                Box(
                    Modifier.padding(horizontal = 3.dp).size(28.dp).clip(CircleShape)
                        .background(c).clickable { colorIndex = i }
                )
            }
            Spacer(Modifier.weight(1f))
            IconButton(onClick = { if (strokes.isNotEmpty()) strokes.removeAt(strokes.lastIndex) }) {
                Icon(Icons.Filled.Undo, "Undo", tint = Color.White)
            }
            IconButton(onClick = {
                strokes.clear(); current = null
                sync?.let { s -> scope.launch { s.sendBoard(WhiteboardEvent("clear", null, null, null, null)) } }
            }) {
                Icon(Icons.Filled.Delete, "Clear", tint = Color.White)
            }
        }
    }
}

private fun androidx.compose.ui.graphics.drawscope.DrawScope.drawStroke(points: List<Offset>, color: Color, width: Float) {
    if (points.size < 2) return
    for (i in 1 until points.size) {
        drawLine(color = color, start = points[i - 1], end = points[i], strokeWidth = width, cap = StrokeCap.Round)
    }
}
