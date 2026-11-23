package io.skwod.app

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MusicNote
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/** Fetches iTunes Search results: one fixed Apple host, no cookies, no redirects, bounded read. */
object MusicSearchClient {
    private val http by lazy {
        OkHttpClient.Builder().followRedirects(false).followSslRedirects(false)
            .connectTimeout(10, TimeUnit.SECONDS).readTimeout(10, TimeUnit.SECONDS).build()
    }

    /** Songs for `term`; null when the search could not be made (offline). */
    suspend fun search(term: String): List<MusicTrack>? = withContext(Dispatchers.IO) {
        val url = MusicSearch.url(term) ?: return@withContext emptyList()
        if (!MusicHosts.isAppleHost(url)) return@withContext null
        try {
            http.newCall(Request.Builder().url(url).header("Accept", "application/json").build()).execute().use { res ->
                if (!res.isSuccessful) return@use null
                val source = res.body?.source() ?: return@use null
                // Never more than MAX_BYTES, whatever the server sends.
                source.request(MusicSearch.MAX_BYTES.toLong() + 1)
                if (source.buffer.size > MusicSearch.MAX_BYTES) return@use null
                MusicSearch.parse(source.buffer.readUtf8())
            }
        } catch (_: Exception) { null }
    }
}

/** Pick a song to share: type, see results from Apple's catalogue, tap one. */
@Composable
fun MusicSearchDialog(onPick: (MusicTrack) -> Unit, onClose: () -> Unit) {
    var term by remember { mutableStateOf("") }
    var results by remember { mutableStateOf<List<MusicTrack>>(emptyList()) }
    var state by remember { mutableStateOf("") }
    LaunchedEffect(term) {
        if (term.isBlank()) { results = emptyList(); state = ""; return@LaunchedEffect }
        delay(400)                                  // one request per pause in typing
        state = "Searching…"
        val found = MusicSearchClient.search(term)
        results = found ?: emptyList()
        state = when {
            found == null -> "Couldn't search — check your connection."
            found.isEmpty() -> "No songs found."
            else -> ""
        }
    }
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("Share a song") },
        text = {
            Column {
                OutlinedTextField(term, { term = it.take(MusicSearch.MAX_TERM) }, placeholder = { Text("Song or artist") },
                    singleLine = true, modifier = Modifier.fillMaxWidth().testTag("music-search"))
                if (state.isNotEmpty()) Text(state, color = Color.White.copy(alpha = 0.6f), fontSize = 13.sp, modifier = Modifier.padding(top = 8.dp))
                LazyColumn(Modifier.heightIn(max = 320.dp).padding(top = 8.dp)) {
                    items(results) { t ->
                        Row(Modifier.fillMaxWidth().clickable { onPick(t) }.padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.MusicNote, null, tint = SkAccent)
                            Spacer(Modifier.width(10.dp))
                            Column {
                                Text(t.title, color = Color.White, maxLines = 1)
                                Text(t.artist, color = Color.White.copy(alpha = 0.6f), fontSize = 12.sp, maxLines = 1)
                            }
                        }
                    }
                }
                Text("Results come from Apple's music catalogue. Searching sends what you type to Apple, not to your skwod.",
                    color = Color.White.copy(alpha = 0.4f), fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onClose) { Text("Cancel") } },
    )
}
