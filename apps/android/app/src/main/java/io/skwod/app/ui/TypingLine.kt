package io.skwod.app

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay

/**
 * "Sam is typing…" just above the composer of the open chat ([topic]). Only `typing` events on
 * this chat's topic count (nothing elsewhere, no notifications); [accept] says who may be shown
 * here at all (a member of this conversation), [nameOf] gives the name through the trust labels.
 * Nothing is shown with "Send typing indicators" off.
 */
@Composable
fun TypingLine(topic: String, accept: (String) -> Boolean, nameOf: (String) -> String) {
    val model = AppModel.get(LocalContext.current)
    val enabled = model.settings.typingIndicators
    var state by remember(topic) { mutableStateOf(TypingState()) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(topic, enabled) {
        state = TypingState()
        if (!enabled) return@LaunchedEffect
        model.realtime.events.collect { ev ->
            if (ev.topic != topic) return@collect
            when (ev.event) {
                "typing" -> {
                    val uid = ev.payload.optString("user_id")
                    if (accept(uid)) {
                        now = System.currentTimeMillis()
                        state = state.add(uid, model.session?.userId, model.isBlockedUser(uid), enabled, now)
                    }
                }
                // Their message arrived: they are not typing any more.
                "message" -> state = state.remove(ev.payload.optString("author_id"))
            }
        }
    }
    LaunchedEffect(state.until.isEmpty()) {
        while (state.until.isNotEmpty()) {
            delay(500)
            now = System.currentTimeMillis()
            state = state.expire(now)
        }
    }
    val text = TypingState.text(state.typers(now).map(nameOf)) ?: return
    Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
        TypingDots()
        Spacer(Modifier.width(6.dp))
        Text(text, color = Color.White.copy(alpha = 0.55f), fontSize = 12.sp, maxLines = 1)
    }
}

@Composable
private fun TypingDots() {
    val t = rememberInfiniteTransition(label = "typing")
    Row(horizontalArrangement = Arrangement.spacedBy(3.dp), verticalAlignment = Alignment.CenterVertically) {
        for (i in 0 until 3) {
            val a by t.animateFloat(0.25f, 1f, infiniteRepeatable(tween(500, delayMillis = i * 150), RepeatMode.Reverse), label = "dot$i")
            Box(Modifier.size(5.dp).alpha(a).background(Color.White, CircleShape))
        }
    }
}
