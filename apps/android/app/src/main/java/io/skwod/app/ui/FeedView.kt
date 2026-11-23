package io.skwod.app

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The E2EE Feed: posts and stories that ride the active space's channel. Instagram-style square
 * photos with the caption below, likes (synced reactions), and comments (E2EE channel messages).
 */
@Composable
fun FeedView(chat: AppChat) {
    val ctx = LocalContext.current
    val model = AppModel.get(ctx)
    val feed = remember { FeedModel(model, chat) }
    val scope = rememberCoroutineScope()
    var caption by remember { mutableStateOf("") }
    var pending by remember { mutableStateOf<ByteArray?>(null) }
    var commentsFor by remember { mutableStateOf<FeedItem?>(null) }
    var storyView by remember { mutableStateOf<FeedItem?>(null) }
    // One post or story at a time: while one is on its way up, nothing else can be started.
    val posting = feed.sending != null
    var showStoryEditor by remember { mutableStateOf(false) }
    var showPostEditor by remember { mutableStateOf(false) }
    /** A song picked for the post being written (iTunes Search, Apple hosts only). */
    var song by remember { mutableStateOf<MusicTrack?>(null) }
    var showMusic by remember { mutableStateOf(false) }
    if (showMusic) MusicSearchDialog(onPick = { song = it; showMusic = false }, onClose = { showMusic = false })
    // Something was queued, delivered or failed — or someone was blocked: read the feed again.
    val outboxRevision = Outbox.revision.intValue
    LaunchedEffect(outboxRevision) { if (outboxRevision > 0) try { feed.refresh() } catch (_: Exception) {} }

    val postPicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) scope.launch {
            pending = withContext(Dispatchers.IO) { ctx.contentResolver.openInputStream(uri)?.use { it.readBytes() } }
        }
    }

    // Refreshed when the relay reports something in a feed channel (a post, a comment, a like),
    // on reconnect and on a slow safety timer — not every five seconds.
    val serverKey = feed.servers.joinToString(",") { it.first }
    LaunchedEffect(serverKey) {
        model.realtime.refreshLoop(60_000, match = { it.topic in feed.topics }) { feed.refresh() }
    }
    var serverMenu by remember { mutableStateOf(false) }

    if (!feed.hasSpace) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("Join a server to see its feed.", color = Color.White.copy(alpha = 0.5f))
        }
        return
    }

    commentsFor?.let { post ->
        CommentSheet(feed, post, onClose = { commentsFor = null })
        return
    }
    storyView?.let { story ->
        StoryViewer(story, onClose = { storyView = null }, onDelete = { scope.launch { feed.delete(story.id, story.channelId) } })
        return
    }
    if (showStoryEditor) {
        // Instagram-style editor: photo + filters + draggable/recolorable text, flattened to one image.
        StoryEditorScreen(square = false, onClose = { showStoryEditor = false },
            onDone = { bytes, music, clip ->
                showStoryEditor = false
                // A story may be only a song. Progress and failure show in the feed (the ring).
                if (bytes != null || music != null) scope.launch { feed.postStory(bytes, music, clip) }
            })
        return
    }
    if (showPostEditor) {
        StoryEditorScreen(square = true, initialImage = pending, onClose = { showPostEditor = false },
            onDone = { bytes, _, _ -> showPostEditor = false; if (bytes != null) pending = bytes })
        return
    }

    LazyColumn(Modifier.fillMaxSize().padding(horizontal = 12.dp)) {
        item {
            Spacer(Modifier.height(12.dp))
            Text("Feed", color = Color.White, fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(12.dp))
            // Stories row.
            LazyRow(verticalAlignment = Alignment.CenterVertically) {
                item {
                    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(end = 12.dp)) {
                        val sendingStory = feed.sending?.takeIf { it.story }
                        val failedStory = sendingStory == null && feed.failedDraft?.story == true
                        Box(Modifier.size(62.dp).clip(CircleShape).background(Color.White.copy(alpha = 0.08f))
                            .then(if (failedStory) Modifier.border(2.dp, Color(0xFFFB923C), CircleShape) else Modifier)
                            // A story that failed: the ring sends it again. While one is going up, nothing.
                            .clickable(enabled = !posting) { if (failedStory) scope.launch { feed.retryFailed() } else showStoryEditor = true }
                            .testTag("feed-my-story"), contentAlignment = Alignment.Center) {
                            when {
                                sendingStory != null -> {
                                    // The ring fills as the story encrypts and uploads.
                                    CircularProgressIndicator(progress = { sendingStory.fraction }, modifier = Modifier.fillMaxSize(),
                                        color = SkAccent, trackColor = Color.White.copy(alpha = 0.15f), strokeWidth = 3.dp)
                                    if (sendingStory.stage == FeedSend.Stage.UPLOADING) Text("${sendingStory.percent}%", color = Color.White,
                                        style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                                }
                                failedStory -> Icon(Icons.Filled.Refresh, "Send your story again", tint = Color(0xFFFB923C))
                                else -> Icon(Icons.Filled.Add, "Add story", tint = SkAccent)
                            }
                        }
                        Text(if (sendingStory != null) "Sending…" else if (failedStory) "Try again" else "Your story",
                            color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.labelSmall)
                    }
                }
                items(feed.stories) { s ->
                    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(end = 12.dp)) {
                        val bmp = remember(s.id) { s.photo?.let { SafeImage.decodeInbound(it) } }
                        Box(Modifier.size(62.dp).clip(CircleShape)
                            .border(2.dp, SkAccent, CircleShape)
                            .clickable { storyView = s }, contentAlignment = Alignment.Center) {
                            if (bmp != null) Image(bmp.asImageBitmap(), s.author, Modifier.fillMaxSize().clip(CircleShape), contentScale = ContentScale.Crop)
                            else Monogram(s.author, size = 58)
                        }
                        Text(s.author, color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.labelSmall, maxLines = 1)
                    }
                }
            }
            Spacer(Modifier.height(14.dp))
            // A post, story, comment or like that did not go out is said here — never dropped silently.
            // What is on its way out, and how far along.
            feed.sending?.let { s ->
                Column(Modifier.fillMaxWidth().testTag("feed-sending")) {
                    Text(s.label, color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(6.dp))
                    if (s.stage == FeedSend.Stage.UPLOADING) LinearProgressIndicator(progress = { s.uploaded.coerceIn(0f, 1f) },
                        modifier = Modifier.fillMaxWidth(), color = SkAccent, trackColor = Color.White.copy(alpha = 0.15f))
                    else LinearProgressIndicator(Modifier.fillMaxWidth(), color = SkAccent, trackColor = Color.White.copy(alpha = 0.15f))
                }
                Spacer(Modifier.height(10.dp))
            }
            feed.error?.let { msg ->
                Surface(color = Color(0xFFF87171).copy(alpha = 0.12f), shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth()) {
                    Row(Modifier.padding(horizontal = 12.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.ErrorOutline, null, tint = Color(0xFFF87171), modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(msg, color = Color.White, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                        if (feed.failedDraft?.story == true) {
                            // Nothing was lost: the same story can go out again. (A post that
                            // failed is still in the composer below.)
                            TextButton(onClick = { scope.launch { feed.retryFailed() } }, enabled = !posting, modifier = Modifier.testTag("feed-retry")) { Text("Try again") }
                            TextButton(onClick = { feed.discardFailed() }) { Text("Discard", color = Color.White.copy(alpha = 0.6f)) }
                        } else IconButton(onClick = { feed.discardFailed() }, modifier = Modifier.size(24.dp)) {
                            Icon(Icons.Filled.Close, "Dismiss", tint = Color.White.copy(alpha = 0.6f), modifier = Modifier.size(16.dp))
                        }
                    }
                }
                Spacer(Modifier.height(10.dp))
            }
            // Composer.
            Surface(color = GlassCardTone, shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    pending?.let { bytes ->
                        val bmp = remember(bytes) { SafeImage.decode(bytes) }
                        if (bmp != null) Image(bmp.asImageBitmap(), "attached", Modifier.fillMaxWidth().aspectRatio(1f)
                            .clip(RoundedCornerShape(12.dp)), contentScale = ContentScale.Crop)
                        Spacer(Modifier.height(8.dp))
                    }
                    // In more than one server: say where this goes (posts and stories alike).
                    val servers = feed.servers
                    if (servers.size > 1) {
                        Box {
                            Row(Modifier.clip(RoundedCornerShape(50)).background(Color.White.copy(alpha = 0.08f))
                                .clickable { serverMenu = true }.padding(horizontal = 12.dp, vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically) {
                                Text("Post to", color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelMedium)
                                Spacer(Modifier.width(6.dp))
                                Text(feed.targetServer?.second ?: "", color = Color.White, style = MaterialTheme.typography.labelLarge, maxLines = 1)
                                Icon(Icons.Filled.ArrowDropDown, "Choose a server", tint = Color.White.copy(alpha = 0.7f))
                            }
                            DropdownMenu(expanded = serverMenu, onDismissRequest = { serverMenu = false }) {
                                servers.forEach { (sid, name) ->
                                    DropdownMenuItem(text = { Text(name) }, onClick = { feed.postServerId = sid; serverMenu = false },
                                        leadingIcon = { if (sid == feed.targetServer?.first) Icon(Icons.Filled.Check, null) })
                                }
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                    }
                    OutlinedTextField(caption, { caption = it }, placeholder = { Text("Share something…") },
                        modifier = Modifier.fillMaxWidth(), maxLines = 4)
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconButton(onClick = { postPicker.launch("image/*") }) {
                            Icon(Icons.Filled.Image, "Photo", tint = SkAccent)
                        }
                        if (pending != null) {
                            IconButton(onClick = { showPostEditor = true }) {
                                Icon(Icons.Filled.AutoFixHigh, "Edit photo", tint = SkAccent)
                            }
                        }
                        IconButton(onClick = { showMusic = true }) {
                            Icon(Icons.Filled.MusicNote, "Add a song", tint = if (song != null) Color(0xFF4ADE80) else SkAccent)
                        }
                        song?.let { s ->
                            Text("${s.title} ✕", color = Color.White.copy(alpha = 0.8f), maxLines = 1, style = MaterialTheme.typography.labelMedium,
                                modifier = Modifier.weight(1f, fill = false).clickable { song = null })
                        }
                        Spacer(Modifier.weight(1f))
                        Button(onClick = {
                            if (posting) return@Button
                            scope.launch {
                                // Keep the draft when it did not go out (the reason is shown above).
                                if (feed.post(caption.trim(), pending, song)) { caption = ""; pending = null; song = null }
                            }
                        // A song alone is a post.
                        }, enabled = !posting && (caption.isNotBlank() || pending != null || song != null)) {
                            Text(if (posting) "…" else "Post")
                        }
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
        }
        items(feed.posts) { post ->
            PostCard(post, comments = feed.commentsByPost[post.id]?.size ?: post.commentCount,
                onLike = { scope.launch { feed.toggleLike(post) } },
                onComment = { commentsFor = post },
                onDelete = { scope.launch { feed.delete(post.id, post.channelId) } })
            Spacer(Modifier.height(16.dp))
        }
        if (feed.posts.isEmpty()) item {
            Text("No posts yet — be the first.", color = Color.White.copy(alpha = 0.5f),
                modifier = Modifier.padding(24.dp))
        }
    }
}

@Composable
private fun PostCard(post: FeedItem, comments: Int, onLike: () -> Unit, onComment: () -> Unit, onDelete: () -> Unit) {
    var menu by remember { mutableStateOf(false) }
    Surface(color = GlassCardTone, shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth()) {
        Column {
            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Monogram(post.author, size = 34)
                Spacer(Modifier.width(10.dp))
                Text(post.author, color = Color.White, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.weight(1f))
                // My own post: delete it for everyone.
                if (post.mine) Box {
                    IconButton(onClick = { menu = true }, modifier = Modifier.testTag("feed-post-menu")) { Icon(Icons.Filled.MoreVert, "Post options", tint = Color.White.copy(alpha = 0.7f)) }
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        DropdownMenuItem(text = { Text("Delete post") }, onClick = { menu = false; onDelete() },
                            leadingIcon = { Icon(Icons.Filled.Delete, null) })
                    }
                }
            }
            if (post.photo != null || post.attachment != null) {
                FeedPhoto(post, "photo", Modifier.fillMaxWidth().aspectRatio(1f), ContentScale.Crop)
            }
            // A shared song — also when it is the whole post.
            post.music?.let { Box(Modifier.padding(horizontal = 12.dp, vertical = 6.dp)) { MusicContent(it) } }
            if (post.serverName.isNotEmpty()) Text(post.serverName, color = Color.White.copy(alpha = 0.4f),
                style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(start = 12.dp, top = 6.dp))
            Row(Modifier.padding(horizontal = 8.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = onLike) {
                    Icon(if (post.liked) Icons.Filled.Favorite else Icons.Filled.FavoriteBorder, "Like",
                        tint = if (post.liked) Color(0xFFF87171) else Color.White.copy(alpha = 0.8f))
                }
                if (post.likes > 0) Text("${post.likes}", color = Color.White.copy(alpha = 0.8f))
                Spacer(Modifier.width(6.dp))
                IconButton(onClick = onComment) {
                    Icon(Icons.Filled.ChatBubbleOutline, "Comments", tint = Color.White.copy(alpha = 0.8f))
                }
                if (comments > 0) Text("$comments", color = Color.White.copy(alpha = 0.8f))
            }
            if (post.text.isNotBlank()) Text(post.text, color = Color.White,
                modifier = Modifier.padding(horizontal = 12.dp).padding(bottom = 12.dp))
        }
    }
}

@Composable
private fun CommentSheet(feed: FeedModel, post: FeedItem, onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    var draft by remember { mutableStateOf("") }
    var sending by remember { mutableStateOf(false) }
    val comments = feed.commentsByPost[post.id] ?: emptyList()

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onClose) { Icon(Icons.Filled.ArrowBack, "Back", tint = Color.White) }
            Text("Comments", color = Color.White, style = MaterialTheme.typography.titleMedium)
        }
        if (post.text.isNotBlank()) Text(post.text, color = Color.White.copy(alpha = 0.7f), modifier = Modifier.padding(8.dp))
        Spacer(Modifier.height(8.dp))
        LazyColumn(Modifier.weight(1f)) {
            items(comments) { c ->
                Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    Monogram(c.author, size = 28); Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text(c.author, color = seededColor(c.author), style = MaterialTheme.typography.labelMedium)
                        Text(c.text, color = Color.White)
                    }
                    // My own comment: delete it for everyone.
                    if (c.mine) IconButton(onClick = { scope.launch { feed.delete(c.id, post.channelId) } }) {
                        Icon(Icons.Filled.Delete, "Delete comment", tint = Color.White.copy(alpha = 0.5f))
                    }
                }
            }
            if (comments.isEmpty()) item {
                Text("No comments yet.", color = Color.White.copy(alpha = 0.5f), modifier = Modifier.padding(12.dp))
            }
        }
        feed.error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(4.dp)) }
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(draft, { draft = it }, placeholder = { Text("Add a comment…") },
                modifier = Modifier.weight(1f), maxLines = 3)
            Spacer(Modifier.width(8.dp))
            FilledIconButton(onClick = {
                val t = draft.trim(); if (t.isEmpty() || sending) return@FilledIconButton
                sending = true; draft = ""
                scope.launch { if (!feed.comment(post, t)) draft = t; sending = false }
            }, enabled = !sending && draft.isNotBlank(), shape = CircleShape) {
                Icon(Icons.Filled.ArrowUpward, "Send", tint = Color.Black)
            }
        }
    }
}

@Composable
private fun StoryViewer(story: FeedItem, onClose: () -> Unit, onDelete: () -> Unit) {
    // A finger held on the story pauses it — and its song; a tap closes it, as before.
    var held by remember { mutableStateOf(false) }
    Box(Modifier.fillMaxSize().background(Color.Black).pointerInput(Unit) {
        detectTapGestures(onPress = { held = true; try { tryAwaitRelease() } finally { held = false } }, onTap = { onClose() })
    }, contentAlignment = Alignment.Center) {
        // Opening a story IS asking for it: the full picture is fetched now (the row of story
        // circles only ever shows thumbnails). A story may also be only a song.
        if (story.photo != null || story.attachment != null) FeedPhoto(story, story.author, Modifier.fillMaxWidth(), ContentScale.Fit, open = true)
        Row(Modifier.align(Alignment.TopStart).fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Monogram(story.author, size = 32); Spacer(Modifier.width(8.dp))
            Text(story.author, color = Color.White, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.weight(1f))
            // My own story: delete it for everyone.
            if (story.mine) IconButton(onClick = { onDelete(); onClose() }, modifier = Modifier.testTag("story-delete")) {
                Icon(Icons.Filled.Delete, "Delete story", tint = Color.White)
            }
        }
        // The song starts by itself and plays the part its author chose; paused while held
        // and while the app is not in front.
        val owner = androidx.compose.ui.platform.LocalLifecycleOwner.current
        var resumed by remember { mutableStateOf(owner.lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)) }
        DisposableEffect(owner) {
            val observer = androidx.lifecycle.LifecycleEventObserver { _, _ -> resumed = owner.lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED) }
            owner.lifecycle.addObserver(observer)
            onDispose { owner.lifecycle.removeObserver(observer) }
        }
        story.music?.let { StoryMusicBar(it, story.clip, held = held || !resumed, modifier = Modifier.align(Alignment.BottomCenter).padding(24.dp)) }
    }
}

/**
 * A post's or story's picture.
 *
 * WHY THE FEED NEVER FETCHES BY ITSELF: the full picture is an attachment on the host, and a
 * download is made with the viewer's session. Fetching it as a post scrolls into view would tell
 * the host who looked at which post, and when — a read receipt nobody agreed to send. So the
 * feed draws only the small thumbnail that travelled INSIDE the (already delivered) message, and
 * the full picture is fetched when the viewer asks for it: a tap on a post, opening a story
 * ([open] = true). Same as chat. Size does not change this; the hard cap and the bounded read
 * still apply to the fetch itself. Posts from builds ≤ 42 carry the whole picture inline and
 * have no attachment.
 */
@Composable
private fun FeedPhoto(item: FeedItem, description: String, modifier: Modifier, scale: ContentScale, open: Boolean = false) {
    val ctx = LocalContext.current
    val att = item.attachment
    val preview = remember(item.id) { item.photo?.let { SafeImage.decodeInbound(it) } }
    var full by remember(item.id) { mutableStateOf<android.graphics.Bitmap?>(null) }
    var failed by remember(item.id) { mutableStateOf<String?>(null) }
    // A picture is decoded in memory: the fixed 100 MB bound, whatever the host's upload limit is.
    val allowed = att != null && AttachmentLimits.acceptable(att.size, AttachmentLimits.MAX_BYTES)
    // 0 = not asked. Each tap (and each retry after a failure) is one more attempt.
    var attempt by remember(item.id) { mutableIntStateOf(if (open) 1 else 0) }
    var loading by remember(item.id) { mutableStateOf(false) }
    LaunchedEffect(item.id, att?.blobId, attempt) {
        if (att == null || full != null || attempt == 0 || !allowed) return@LaunchedEffect
        val store = AppModel.get(ctx).blobStore() ?: run { failed = "Not connected."; return@LaunchedEffect }
        loading = true; failed = null
        try {
            full = withContext(Dispatchers.IO) { SafeImage.decodeInboundFile(AttachmentService.localFile(ctx, att, store, AttachmentLimits.MAX_BYTES)) }
            if (full == null) failed = "This picture can't be shown."
        } catch (e: kotlinx.coroutines.CancellationException) { throw e
        } catch (e: Exception) { failed = (e as? AttachmentException)?.message ?: "Couldn't load the full picture." }
        finally { loading = false }
    }
    val canAsk = att != null && full == null && allowed && !loading
    Box(modifier.then(if (canAsk) Modifier.clickable { attempt++ } else Modifier), contentAlignment = Alignment.Center) {
        val bmp = full ?: preview
        if (bmp != null) Image(bmp.asImageBitmap(), description, Modifier.fillMaxSize(), contentScale = scale)
        if (att != null && full == null) {
            val label = when {
                loading -> "Loading picture…"
                failed != null -> failed!!
                !allowed -> "This picture is too large to open (${AttachmentService.formattedSize(att.size.coerceAtLeast(0))})."
                else -> "Tap to load the full picture · ${AttachmentService.formattedSize(att.size)}"
            }
            Text(label, color = Color.White, style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.align(Alignment.BottomCenter).padding(8.dp)
                    .clip(RoundedCornerShape(50)).background(Color.Black.copy(alpha = 0.55f))
                    .padding(horizontal = 10.dp, vertical = 5.dp))
        }
    }
}
