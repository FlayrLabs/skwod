package io.skwod.app

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioFocusRequest
import android.media.AudioManager
import android.media.MediaPlayer
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.MusicNote
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material.icons.filled.VolumeOff
import androidx.compose.material.icons.filled.VolumeUp
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay

/**
 * Plays the chosen part of a story's song — the Android peer of the Apple app's
 * `StoryClipPlayer`: in the viewer (starts by itself, loops, pauses while the story is held)
 * and in the composer (hearing the part while picking it).
 *
 * The audio is the song's PREVIEW — the one source every viewer can play, with no account. It
 * is NEVER fetched from Apple by this phone (that would show Apple every viewer's IP address):
 * the viewer's own Skwod host fetches it ([BlobStore.musicPreview], see [StoryMusicPolicy]),
 * and what plays is that answer, from a private temporary file. It plays as media (the media
 * volume), and asks for transient audio focus so other apps' music pauses for it and comes back.
 */
class StoryClipPlayer(private val ctx: Context) {
    var unavailable by mutableStateOf(false)
        private set
    /** Why, when [unavailable]. */
    var problem by mutableStateOf("no preview to play")
        private set
    /** The host is being asked for the audio. */
    var loading by mutableStateOf(false)
        private set
    private var file: java.io.File? = null
    var playing by mutableStateOf(false)
        private set
    /** The real length of the loaded preview (null until it is known). */
    var previewMs by mutableStateOf<Int?>(null)
        private set

    private var player: MediaPlayer? = null
    private var prepared = false
    private var clip = MusicClip.FALLBACK
    private var held = false
    private var muted = false
    private var focus: AudioFocusRequest? = null
    private val audio get() = ctx.getSystemService(Context.AUDIO_SERVICE) as AudioManager

    /**
     * Ask the host for the preview, then play [clip] of it. Suspends while the host answers;
     * cancelling (the story closed) abandons it.
     */
    suspend fun start(track: MusicTrack, clip: MusicClip, muted: Boolean, store: BlobStore?) {
        stop()
        this.clip = clip
        this.muted = muted
        val url = StoryMusicPolicy.hostFetchable(track.previewUrl)
        if (url == null || store == null) { problem = "no preview to play"; unavailable = true; return }
        unavailable = false
        loading = true
        val dir = java.io.File(ctx.cacheDir, "skwod-story-music").apply { mkdirs() }
        val dest = java.io.File(dir, "${java.util.UUID.randomUUID()}.m4a")
        try { store.musicPreview(url, dest) }
        catch (e: BlobStore.MusicPreviewException) {
            loading = false
            problem = if (e.hostTooOld) "this Skwod's host needs an update to play story music" else "couldn't load the song"
            unavailable = true
            return
        }
        catch (e: kotlinx.coroutines.CancellationException) { dest.delete(); loading = false; throw e }
        loading = false
        file = dest
        begin(dest.absolutePath)
    }

    /** Play the audio the host handed over. */
    private fun begin(path: String) {
        val attrs = AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_MEDIA).setContentType(AudioAttributes.CONTENT_TYPE_MUSIC).build()
        val p = MediaPlayer()
        player = p
        try {
            p.setAudioAttributes(attrs)
            p.setDataSource(path)
            p.setOnPreparedListener {
                if (player !== p) return@setOnPreparedListener
                prepared = true
                previewMs = p.duration.takeIf { d -> d > 0 }
                applyVolume()
                loop()
            }
            p.setOnCompletionListener { if (player === p) loop() }
            p.setOnErrorListener { _, _, _ -> if (player === p) { unavailable = true; release() }; true }
            p.prepareAsync()
        } catch (_: Exception) { unavailable = true; release() }
    }

    /** Back to the start of the chosen part, and on (unless held). */
    private fun loop() {
        val p = player ?: return
        if (!prepared) return
        try {
            p.seekTo(clip.window(previewMs).first)
            if (held) { if (p.isPlaying) p.pause(); playing = false } else { requestFocus(); p.start(); playing = true }
        } catch (_: IllegalStateException) {}
    }

    /** Called a few times a second while a story is open: the end of the part loops it. */
    fun tick() {
        val p = player ?: return
        if (!prepared || !playing) return
        try { if (p.currentPosition >= clip.window(previewMs).second) loop() } catch (_: IllegalStateException) {}
    }

    fun setClip(next: MusicClip) { if (next != clip) { clip = next; loop() } }

    fun setHeld(now: Boolean) {
        if (now == held) return
        held = now
        val p = player ?: return
        if (!prepared) return
        try {
            if (held) { if (p.isPlaying) p.pause(); playing = false } else { requestFocus(); p.start(); playing = true }
        } catch (_: IllegalStateException) {}
    }

    fun setMuted(now: Boolean) { muted = now; applyVolume() }

    private fun applyVolume() { try { player?.setVolume(if (muted) 0f else 1f, if (muted) 0f else 1f) } catch (_: IllegalStateException) {} }

    private fun requestFocus() {
        if (focus != null) return
        val request = AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN_TRANSIENT)
            .setAudioAttributes(AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_MEDIA).setContentType(AudioAttributes.CONTENT_TYPE_MUSIC).build())
            .setOnAudioFocusChangeListener { change -> if (change < 0) setHeldByFocus() }
            .build()
        runCatching { audio.requestAudioFocus(request) }
        focus = request
    }

    /** Another app (or a call) took the audio: stop sounding; the story has to be reopened. */
    private fun setHeldByFocus() { try { player?.takeIf { prepared && it.isPlaying }?.pause() } catch (_: IllegalStateException) {}; playing = false }

    private fun release() {
        try { player?.release() } catch (_: Exception) {}
        player = null; prepared = false; playing = false
        focus?.let { runCatching { audio.abandonAudioFocusRequest(it) } }
        focus = null
    }

    fun stop() {
        release(); held = false; previewMs = null; unavailable = false; loading = false
        file?.delete(); file = null
    }
}

/** The viewer's own mute, remembered across stories and launches. */
object StoryMute {
    private const val PREFS = "skwod-story"
    private const val KEY = "muted"
    fun get(ctx: Context): Boolean = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY, false)
    fun set(ctx: Context, muted: Boolean) { ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY, muted).apply() }
}

@Composable
private fun rememberClipPlayer(): StoryClipPlayer {
    val ctx = LocalContext.current.applicationContext
    val player = remember { StoryClipPlayer(ctx) }
    DisposableEffect(Unit) { onDispose { player.stop() } }
    LaunchedEffect(player) { while (true) { delay(60); player.tick() } }
    return player
}

/**
 * The song on an open story: it starts by itself, plays the part its author chose ([clip]; a
 * story from a build before 45 plays the first 15 seconds), loops while the story is open and
 * pauses while it is [held]. One tap mutes (remembered).
 */
@Composable
fun StoryMusicBar(track: MusicTrack, clip: MusicClip?, held: Boolean, modifier: Modifier = Modifier) {
    val ctx = LocalContext.current
    val player = rememberClipPlayer()
    var muted by remember { mutableStateOf(StoryMute.get(ctx)) }
    // Never over a call: the call owns the audio.
    val inCall = remember { (ctx.getSystemService(Context.AUDIO_SERVICE) as AudioManager).mode == AudioManager.MODE_IN_COMMUNICATION }
    // "Play story music only when I tap": nothing is fetched until this story's song is tapped.
    val tapToPlay = AppSettings.get(ctx).storyMusicTapToPlay
    var tapped by remember(track.id, track.previewUrl) { mutableStateOf(false) }
    val onOpen = StoryMusicPolicy.onOpen(tapToPlay, tapped, inCall, StoryMusicPolicy.hostFetchable(track.previewUrl) != null)
    LaunchedEffect(track.id, track.previewUrl, clip, onOpen) {
        if (onOpen == StoryMusicPolicy.OnOpen.FETCH) player.start(track, clip ?: MusicClip.FALLBACK, muted, AppModel.get(ctx).blobStore())
    }
    LaunchedEffect(held) { player.setHeld(held) }
    Row(modifier.clip(RoundedCornerShape(14.dp)).background(Color.Black.copy(alpha = 0.45f)).padding(10.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Icon(Icons.Filled.MusicNote, null, tint = if (player.playing && !muted) SkAccent else Color.White.copy(alpha = 0.6f), modifier = Modifier.size(24.dp))
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f, fill = false)) {
            Text(track.title, color = Color.White, maxLines = 1, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            Text(when {
                onOpen == StoryMusicPolicy.OnOpen.WAIT_FOR_TAP -> "${track.artist.ifBlank { "Apple Music" }} · tap to play"
                onOpen == StoryMusicPolicy.OnOpen.SILENT && !inCall -> "${track.artist.ifBlank { "Apple Music" }} · no preview to play"
                player.unavailable -> "${track.artist.ifBlank { "Apple Music" }} · ${player.problem}"
                muted -> "${track.artist.ifBlank { "Apple Music" }} · muted"
                else -> track.artist.ifBlank { "Apple Music" }
            }, color = Color.White.copy(alpha = 0.65f), maxLines = 1, style = MaterialTheme.typography.labelSmall)
        }
        if (onOpen == StoryMusicPolicy.OnOpen.WAIT_FOR_TAP) {
            Spacer(Modifier.width(10.dp))
            Box(Modifier.size(34.dp).clip(CircleShape).background(SkAccent).clickable { tapped = true }.testTag("story-play-music"),
                contentAlignment = Alignment.Center) {
                Icon(Icons.Filled.PlayArrow, "Play this story's song", tint = Color.Black, modifier = Modifier.size(20.dp))
            }
        } else if (player.loading) {
            Spacer(Modifier.width(10.dp))
            CircularProgressIndicator(Modifier.size(22.dp), color = Color.White, strokeWidth = 2.dp)
        } else if (onOpen == StoryMusicPolicy.OnOpen.FETCH && !player.unavailable) {
            Spacer(Modifier.width(10.dp))
            Box(Modifier.size(34.dp).clip(CircleShape).background(Color.White.copy(alpha = 0.14f))
                .clickable { muted = !muted; StoryMute.set(ctx, muted); player.setMuted(muted) }.testTag("story-mute"),
                contentAlignment = Alignment.Center) {
                Icon(if (muted) Icons.Filled.VolumeOff else Icons.Filled.VolumeUp, if (muted) "Unmute" else "Mute", tint = Color.White, modifier = Modifier.size(18.dp))
            }
        }
    }
}

/**
 * "Which part plays": the song, a length (5 / 10 / 15 s) and a strip of the preview with a
 * window to drag. The selection plays, looped, while it is being chosen. The bars are a drawing
 * (the same for a given song each time), not the measured waveform.
 */
@Composable
fun MusicClipTrimmer(track: MusicTrack, clip: MusicClip, onClip: (MusicClip) -> Unit, onRemove: () -> Unit, modifier: Modifier = Modifier) {
    val ctx = LocalContext.current
    val player = rememberClipPlayer()
    val previewMs = player.previewMs ?: MusicClip.ASSUMED_PREVIEW_MS
    val (startMs, endMs) = clip.window(previewMs)
    // The author picked this song and is choosing its part: fetched (via the host) at once.
    LaunchedEffect(track.id, track.previewUrl) { player.start(track, clip, StoryMute.get(ctx), AppModel.get(ctx).blobStore()) }
    LaunchedEffect(clip) { player.setClip(clip) }
    // The preview turned out shorter than assumed: keep the selection inside it.
    LaunchedEffect(player.previewMs) {
        val real = player.previewMs ?: return@LaunchedEffect
        val (s, e) = clip.window(real)
        val fitted = MusicClip.of(s, e - s)
        if (fitted != clip) onClip(fitted)
    }
    val current by rememberUpdatedState(clip)
    val currentPreview by rememberUpdatedState(previewMs)
    Column(modifier.clip(RoundedCornerShape(16.dp)).background(Color.Black.copy(alpha = 0.55f)).padding(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.MusicNote, null, tint = Color.White, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
            Text("${track.title} — ${track.artist}", color = Color.White, maxLines = 1, style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            Icon(Icons.Filled.Close, "Remove song", tint = Color.White, modifier = Modifier.size(22.dp).clip(CircleShape).clickable(onClick = onRemove).padding(3.dp))
        }
        Spacer(Modifier.height(10.dp))
        if (player.unavailable) {
            Text("This song can't be played here (${player.problem}), so it will show on your story without sound.",
                color = Color.White.copy(alpha = 0.7f), style = MaterialTheme.typography.labelSmall)
            return@Column
        }
        var widthPx by remember { mutableStateOf(1) }
        var dragStartMs by remember { mutableStateOf(0f) }
        Box(Modifier.fillMaxWidth().height(44.dp).onSizeChanged { widthPx = it.width.coerceAtLeast(1) }.testTag("story-clip-strip")
            .pointerInput(Unit) {
                detectTapGestures { at ->
                    // A tap moves the window so that it is centred there.
                    val dur = current.durationMs
                    onClip(MusicClip.chosen((at.x / widthPx * currentPreview - dur / 2).toInt() / 100 * 100, dur / 1000, currentPreview))
                }
            }
            .pointerInput(Unit) {
                detectDragGestures(onDragStart = { dragStartMs = current.window(currentPreview).first.toFloat() }) { change, drag ->
                    change.consume()
                    dragStartMs += drag.x / widthPx * currentPreview
                    // Whole tenths of a second: the player is not restarted for every pixel.
                    val next = MusicClip.chosen(dragStartMs.toInt() / 100 * 100, current.durationMs / 1000, currentPreview)
                    if (next != current) onClip(next)
                }
            }) {
            Row(Modifier.fillMaxSize(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                val bars = 44
                for (i in 0 until bars) {
                    val centerMs = (i + 0.5f) / bars * previewMs
                    val inside = centerMs >= startMs && centerMs <= endMs
                    Box(Modifier.weight(1f).height((6 + 30 * barHeight(i, track.id)).dp).clip(RoundedCornerShape(50))
                        .background(if (inside) SkAccent else Color.White.copy(alpha = 0.3f)))
                }
            }
        }
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            MusicClip.DURATION_CHOICES.forEach { seconds ->
                val on = clip.durationMs == seconds * 1000
                Text("${seconds}s", color = if (on) Color.Black else Color.White, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.padding(end = 8.dp).clip(RoundedCornerShape(50)).background(if (on) Color.White else Color.White.copy(alpha = 0.15f))
                        .clickable { onClip(MusicClip.chosen(clip.startMs, seconds, previewMs)) }.testTag("story-clip-$seconds")
                        .padding(horizontal = 12.dp, vertical = 6.dp))
            }
            Spacer(Modifier.weight(1f))
            Text("${MusicClip.clock(startMs)} – ${MusicClip.clock(endMs)}", color = Color.White.copy(alpha = 0.75f), style = MaterialTheme.typography.labelMedium)
        }
    }
}

/** 0.25…1, the same for a given song and bar every time. */
private fun barHeight(index: Int, seed: String): Float {
    var h = 1469598103934665603L
    for (b in seed.toByteArray()) h = (h xor (b.toLong() and 0xff)) * 1099511628211L
    h = (h xor (index + 1).toLong()) * 1099511628211L
    h = h xor (h ushr 29)
    return 0.25f + 0.75f * (((h % 1000) + 1000) % 1000) / 1000f
}
