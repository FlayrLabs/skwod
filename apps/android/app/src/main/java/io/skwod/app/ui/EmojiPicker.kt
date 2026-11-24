package io.skwod.app

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

/** Build 49: the emoji picker as a bottom sheet — search, recents, a category strip and a grid
 *  that fills the width (the Apple app's `EmojiPickerView`). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EmojiPickerSheet(onPick: (String) -> Unit, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var query by remember { mutableStateOf("") }
    val recents = remember { EmojiCatalog.recents(ctx) }
    val grid = rememberLazyGridState()
    // Index of each section header in the grid (recents first when there are any).
    val sections = remember(recents) {
        var i = if (recents.isEmpty()) 0 else recents.size + 1
        EmojiCatalog.categories.map { c -> val at = i; i += c.emoji.size + 1; at }
    }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = Color(0xFF1C1D22)) {
        Column(Modifier.fillMaxHeight(0.75f).padding(horizontal = 12.dp)) {
            OutlinedTextField(query, { query = it }, singleLine = true, placeholder = { Text("Search emoji") },
                leadingIcon = { Icon(Icons.Filled.Search, null) }, modifier = Modifier.fillMaxWidth())
            if (query.isBlank()) Row(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                EmojiCatalog.categories.forEachIndexed { i, c ->
                    Text(c.emoji.first(), fontSize = 18.sp, modifier = Modifier.weight(1f).clickable { scope.launch { grid.scrollToItem(sections[i]) } }
                        .padding(vertical = 4.dp), textAlign = androidx.compose.ui.text.style.TextAlign.Center)
                }
            }
            LazyVerticalGrid(GridCells.Adaptive(44.dp), state = grid, modifier = Modifier.fillMaxSize()) {
                fun cells(list: List<String>) = items(list) { e ->
                    Text(e, fontSize = 26.sp, textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                        modifier = Modifier.clip(RoundedCornerShape(8.dp)).clickable { EmojiCatalog.noteUsed(ctx, e); onPick(e); onDismiss() }.padding(vertical = 8.dp))
                }
                fun header(t: String) = item(span = { GridItemSpan(maxLineSpan) }) {
                    Text(t.uppercase(), color = Color.White.copy(alpha = 0.5f), fontSize = 11.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(vertical = 6.dp))
                }
                if (query.isNotBlank()) cells(EmojiCatalog.search(query))
                else {
                    if (recents.isNotEmpty()) { header("Recently used"); cells(recents) }
                    for (c in EmojiCatalog.categories) { header(c.title); cells(c.emoji) }
                }
            }
        }
    }
}
