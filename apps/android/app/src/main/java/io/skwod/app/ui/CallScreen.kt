package io.skwod.app

import android.Manifest
import android.content.pm.PackageManager
import android.util.Base64
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.core.content.ContextCompat
import io.livekit.android.LiveKit
import io.livekit.android.RoomOptions
import io.livekit.android.e2ee.BaseKeyProvider
import io.livekit.android.e2ee.E2EEOptions
import io.livekit.android.events.RoomEvent
import io.livekit.android.events.collect
import io.livekit.android.renderer.TextureViewRenderer
import io.livekit.android.room.Room
import io.livekit.android.room.participant.Participant
import io.livekit.android.room.track.LocalVideoTrack
import io.livekit.android.room.track.Track
import io.livekit.android.room.track.VideoTrack
import io.livekit.android.util.flow
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** What the call screen learned, for the DEBUG end-to-end hooks (never shown, never logged). */
object CallDebug {
    @Volatile var phase: String = "idle"
    @Volatile var remoteParticipants: Int = 0
    @Volatile var remoteVideoTracks: Int = 0
    @Volatile var remoteAudioTracks: Int = 0
    @Volatile var keysRegistered: Int = 0
    @Volatile var cameraOn: Boolean = false
}

/**
 * A real end-to-end-encrypted LiveKit call (voice + video) for the skwod's voice channel.
 *
 * Media is encrypted on-device, per frame, with per-call random keys the core generates and sends
 * over sealed libsignal sessions only — the SFU on the host forwards ciphertext. Audio AND video
 * tracks go through the same key provider, so turning the camera on adds nothing the server can
 * read. Fail-closed: no keys → we refuse to connect (ADR-007).
 *
 * For a p2p skwod, `voiceToken` returns a loopback LiveKit URL: signaling and media both travel
 * through the p2p session to the host, and LiveKit's only ICE candidate is 127.0.0.1.
 */
@Composable
fun VoiceCallScreen(serverId: String, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val model = AppModel.get(ctx)
    var phase by remember { mutableStateOf("preparing") } // preparing | connecting | connected | failed
    var errorText by remember { mutableStateOf("") }
    val roomState = remember { mutableStateOf<Room?>(null) }
    var channelId by remember { mutableStateOf<String?>(null) }
    var micGranted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(ctx, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED)
    }
    val micPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) micGranted = true
        else { errorText = "Skwod needs microphone access for calls. Allow it in Settings and try again."; phase = "failed" }
    }

    fun teardown() {
        roomState.value?.let { r -> r.disconnect(); r.release() }
        roomState.value = null
        CallState.active.value = false
        CallDebug.phase = "idle"; CallDebug.cameraOn = false; CallDebug.remoteParticipants = 0
        CallService.stop(ctx)
    }

    // Leaving the screen must synchronously kill the call: Room.disconnect()/release() are plain
    // (non-suspend) calls, and a coroutine launched here would be cancelled in this same disposal
    // pass before it ever ran — leaving a live microphone behind a closed UI.
    DisposableEffect(Unit) { onDispose { teardown() } }

    // The ongoing-call notification's "Hang up" button.
    val hangups = CallState.hangupRequests.intValue
    val initialHangups = remember { hangups }
    LaunchedEffect(hangups) { if (hangups != initialHangups) { teardown(); onClose() } }

    LaunchedEffect(Unit) {
        // A ring for this call is answered by being here.
        if (model.incomingCall?.serverId == serverId) model.incomingCall = null
        Notifications.cancelIncomingCall(ctx)
        if (!micGranted) micPermission.launch(Manifest.permission.RECORD_AUDIO)
    }

    LaunchedEffect(micGranted) {
        if (!micGranted) return@LaunchedEffect
        val client = model.client
        val me = model.session?.userId
        if (client == null || me == null) { errorText = "You're not signed in."; phase = "failed"; return@LaunchedEffect }
        try {
            val chanId = withContext(Dispatchers.IO) { client.ensureVoiceChannel(serverId, "General") }
            channelId = chanId
            // FAIL CLOSED if this device can't do E2EE for the channel (not registered, no sender
            // certificate). The real per-call keys are generated after connect, once we know the
            // room session id.
            val precheck = withContext(Dispatchers.IO) { client.voiceKeys(chanId, me, null) }
            if (precheck.isEmpty()) {
                errorText = "Couldn't set up encryption yet. Open the server's chat so keys sync, then start the call again."
                phase = "failed"; return@LaunchedEffect
            }
            // WebRTC's native library must be loaded BEFORE the key provider is created (its
            // constructor calls into it); LiveKit.create alone would be too late.
            LiveKit.init(ctx.applicationContext)
            val keyProvider = BaseKeyProvider(enableSharedKey = false)
            val tok = withContext(Dispatchers.IO) { client.voiceToken(chanId) }
            val url = tok.url
            if (url.isNullOrEmpty()) { errorText = "Calls aren't set up on this Skwod."; phase = "failed"; return@LaunchedEffect }
            phase = "connecting"; CallDebug.phase = "connecting"
            // The keyring is still empty here, which is itself fail-closed: nothing can be decrypted
            // or published until keys are registered below.
            val room = LiveKit.create(
                appContext = ctx.applicationContext,
                options = RoomOptions(e2eeOptions = E2EEOptions(keyProvider = keyProvider)),
            )
            roomState.value = room
            withContext(Dispatchers.IO) { room.connect(url, tok.token) }
            // Per-call keys: each device generates a RANDOM media key for this room session and sends
            // it — over sealed libsignal sessions only — to the people in the call (LiveKit identity
            // == user id). When one of them drops out of the participant list the core hands back a
            // fresh key at the next key index, so a leaver can't decrypt what is said afterwards.
            // The mic goes live only after our own key is registered; the camera only on request.
            val salt = room.getSid().sid
            var firstOwnIndex: Int? = null
            val registerAll: suspend () -> Int = {
                val participants = room.remoteParticipants.values.mapNotNull { it.identity?.value } + me
                val keys = withContext(Dispatchers.IO) { client.voiceSync(chanId, me, salt, participants) }
                keys.forEach { k ->
                    // base64 keeps the 32 raw bytes identical across Mac/iOS/Android; core returns
                    // our own key last.
                    keyProvider.setKey(Base64.encodeToString(k.key, Base64.NO_WRAP), k.identity, k.keyIndex.toInt())
                }
                // Registering a key does NOT make it the one we encrypt with. The SDK reads the
                // sender's key index ONCE, when a track is published (`getLatestKeyIndex`), and
                // keeps it: after a rotation (someone left) our frames would go on being sealed
                // under the OLD key — which the leaver still holds. Point every one of our
                // senders at our current index explicitly (the Apple client's
                // `setCurrentKeyIndex`). If that cannot be done after a rotation, the call ends:
                // voice E2EE fails closed (ADR-007).
                keys.lastOrNull { it.identity == me }?.let { own ->
                    val index = own.keyIndex.toInt()
                    val applied = SenderKeyIndex.apply(room, me, index)
                    if (firstOwnIndex == null) firstOwnIndex = index
                    if (!applied && index != firstOwnIndex) throw KeyRotationFailed()
                }
                CallDebug.keysRegistered = keys.size
                keys.size
            }
            if (registerAll() == 0) { errorText = "Couldn't set up this call's keys."; phase = "failed"; return@LaunchedEffect }
            // The call outlives the app being in front: a foreground service (phoneCall +
            // microphone/camera) keeps capture alive when the user switches apps.
            CallState.active.value = true
            CallService.start(ctx)
            room.localParticipant.setMicrophoneEnabled(true)
            phase = "connected"; CallDebug.phase = "connected"
            // Keep keys in step with who is in the call (joiners get our key, a leaver triggers a
            // rotation) — mirrors the Apple client's refresh loop. The 2 s poll bounds how long a
            // leaver could still decrypt.
            while (true) {
                delay(2000)
                try { registerAll() } catch (e: KeyRotationFailed) { throw e } catch (_: Exception) {}
            }
        } catch (c: CancellationException) {
            throw c // the screen is closing — never report cancellation as a call failure
        } catch (_: KeyRotationFailed) {
            // Someone left and we could not switch to the new key: stop sending rather than keep
            // encrypting under a key they hold.
            try { roomState.value?.disconnect() } catch (_: Exception) {}
            errorText = "This call's encryption keys couldn't be updated after someone left, so the call was ended."; phase = "failed"
        } catch (e: uniffi.skwod_core.CoreException.UpdateRequired) {
            errorText = "Update required: this Skwod and this app use different encryption versions."; phase = "failed"
        } catch (_: Exception) {
            errorText = "Couldn't join the call. Check your connection and try again."; phase = "failed"
        } catch (_: LinkageError) {
            // The media engine failed to load on this device: fail the call, never the app.
            errorText = "Calls aren't supported on this device."; phase = "failed"
        }
    }

    Box(Modifier.fillMaxSize().background(Color(0xFF0A0A12)), contentAlignment = Alignment.Center) {
        Column(Modifier.fillMaxSize().padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Spacer(Modifier.height(8.dp))
            Text("Call · General", color = Color.White, style = MaterialTheme.typography.titleLarge)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Lock, null, tint = Color(0xFF4ADE80), modifier = Modifier.size(14.dp))
                Spacer(Modifier.width(4.dp))
                Text("End-to-end encrypted", color = Color(0xFF4ADE80), style = MaterialTheme.typography.labelMedium)
            }
            Spacer(Modifier.height(10.dp))
            when (phase) {
                "preparing", "connecting" -> Column(Modifier.weight(1f), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(color = Color.White)
                    Spacer(Modifier.height(12.dp))
                    Text(if (phase == "preparing") "Setting up encryption…" else "Connecting…", color = Color.White.copy(alpha = 0.6f))
                    Spacer(Modifier.height(20.dp))
                    TextButton(onClick = { teardown(); onClose() }) { Text("Cancel") }
                }
                "failed" -> Column(Modifier.weight(1f), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(Icons.Filled.GppMaybe, null, tint = Color(0xFFF59E0B), modifier = Modifier.size(50.dp))
                    Spacer(Modifier.height(10.dp))
                    Text(errorText, color = Color.White.copy(alpha = 0.75f), modifier = Modifier.padding(horizontal = 24.dp))
                    Spacer(Modifier.height(14.dp))
                    Button(onClick = { teardown(); onClose() }) { Text("Close") }
                }
                "connected" -> roomState.value?.let { room ->
                    // Synchronous teardown (see onDispose note) + null out so dispose can't double-release.
                    ConnectedCall(room, channelId, onLeave = { teardown(); onClose() })
                }
            }
        }
    }
}

/** The connected call: participant tiles (video when published), then the controls. */
@Composable
private fun ColumnScope.ConnectedCall(room: Room, channelId: String?, onLeave: () -> Unit) {
    val ctx = LocalContext.current
    val model = AppModel.get(ctx)
    val scope = rememberCoroutineScope()
    var micOn by remember { mutableStateOf(true) }
    var camOn by remember { mutableStateOf(false) }
    var rang by remember { mutableStateOf(false) }
    val remotes by room::remoteParticipants.flow.collectAsState()
    // Tracks come and go without the participant map changing: bump a counter on any room event
    // that affects what a tile shows, so tiles re-read their track.
    var revision by remember { mutableIntStateOf(0) }
    LaunchedEffect(room) {
        room.events.collect { e ->
            when (e) {
                is RoomEvent.TrackSubscribed, is RoomEvent.TrackUnsubscribed, is RoomEvent.TrackMuted,
                is RoomEvent.TrackUnmuted, is RoomEvent.TrackPublished, is RoomEvent.TrackUnpublished,
                is RoomEvent.ParticipantConnected, is RoomEvent.ParticipantDisconnected -> revision++
                else -> {}
            }
        }
    }
    val camPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) scope.launch {
            camOn = try { room.localParticipant.setCameraEnabled(true); true } catch (_: Exception) { false }
            CallDebug.cameraOn = camOn
            if (camOn) CallService.start(ctx)        // re-declare the service with the camera type
            revision++
        }
    }
    fun toggleCamera() {
        if (!camOn && ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            camPermission.launch(Manifest.permission.CAMERA); return
        }
        val want = !camOn
        scope.launch {
            camOn = try { room.localParticipant.setCameraEnabled(want); want } catch (_: Exception) { false }
            CallDebug.cameraOn = camOn
            if (camOn) CallService.start(ctx)
            revision++
        }
    }
    // DEBUG e2e hook: turn the camera on without a tap.
    LaunchedEffect(Unit) { if (E2E.wantsCamera()) { delay(1500); toggleCamera() } }

    val everyone: List<Participant> = remember(remotes, revision) { listOf<Participant>(room.localParticipant) + remotes.values }
    // LiveKit identity == user id; show the member's username on their tile.
    var names by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
    LaunchedEffect(remotes.size) {
        val c = model.client ?: return@LaunchedEffect
        val found = HashMap<String, String>()
        for (sid in model.chat.spaces.map { it.serverId }.distinct()) {
            try { withContext(Dispatchers.IO) { c.listMembers(sid) }.forEach { found[it.userId] = it.username } } catch (_: Exception) {}
        }
        names = found
    }
    SideEffect {
        CallDebug.remoteParticipants = remotes.size
        CallDebug.remoteVideoTracks = remotes.values.count { videoTrackOf(it) != null }
        CallDebug.remoteAudioTracks = remotes.values.count { p -> p.getTrackPublication(Track.Source.MICROPHONE)?.track != null }
    }

    Text("In the call · ${remotes.size + 1} connected", color = Color.White.copy(alpha = 0.8f))
    Spacer(Modifier.height(10.dp))
    LazyVerticalGrid(columns = GridCells.Fixed(if (everyone.size <= 1) 1 else 2), modifier = Modifier.weight(1f).fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(everyone, key = { it.sid.value }) { p ->
            val local = p === room.localParticipant
            // The member list and the participant's own name are the server's word: the tile's
            // label goes through the contact book (pinned name for someone known or verified,
            // a marker for everyone else, a warning for a look-alike).
            val pid = p.identity?.value ?: ""
            val label = if (local) "You" else MemberLabel.of(model.contacts.shown(pid, names[pid] ?: p.name?.takeIf { it.isNotBlank() }), pid)
            ParticipantTile(room, p, revision, label, mirror = local)
        }
    }
    Spacer(Modifier.height(12.dp))
    if (remotes.isEmpty() && channelId != null) {
        TextButton(enabled = !rang, onClick = {
            rang = true
            // Rings every member who could pick up; their devices show an incoming-call screen.
            scope.launch { model.httpSend("api/channels/$channelId/ring", "POST", "{}") }
        }) { Text(if (rang) "Ringing everyone…" else "Ring everyone") }
    }
    Row(horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.CenterVertically) {
        CallButton(if (micOn) Icons.Filled.Mic else Icons.Filled.MicOff, "Microphone", active = micOn) {
            micOn = !micOn
            scope.launch { try { room.localParticipant.setMicrophoneEnabled(micOn) } catch (_: Exception) {} }
        }
        CallButton(if (camOn) Icons.Filled.Videocam else Icons.Filled.VideocamOff, "Camera", active = camOn) { toggleCamera() }
        if (camOn) {
            CallButton(Icons.Filled.Cameraswitch, "Switch camera", active = true) {
                (room.localParticipant.getTrackPublication(Track.Source.CAMERA)?.track as? LocalVideoTrack)?.let { t ->
                    try { t.switchCamera() } catch (_: Exception) {}
                }
            }
        }
        IconButton(onClick = onLeave, modifier = Modifier.size(56.dp).background(Color(0xFFEF4444), CircleShape)) {
            Icon(Icons.Filled.CallEnd, "Leave", tint = Color.White)
        }
    }
    Spacer(Modifier.height(8.dp))
}

@Composable
private fun CallButton(icon: androidx.compose.ui.graphics.vector.ImageVector, label: String, active: Boolean, onClick: () -> Unit) {
    IconButton(onClick = onClick,
        modifier = Modifier.size(56.dp).background(if (active) Color.White.copy(alpha = 0.12f) else Color(0xFF52525B), CircleShape)) {
        Icon(icon, label, tint = Color.White)
    }
}

private fun videoTrackOf(p: Participant): VideoTrack? {
    val pub = p.getTrackPublication(Track.Source.CAMERA) ?: return null
    if (pub.muted) return null
    return pub.track as? VideoTrack
}

/** One participant: their (decrypted) camera video when they publish one, else an initial. */
@Composable
private fun ParticipantTile(room: Room, p: Participant, revision: Int, label: String, mirror: Boolean) {
    val track = remember(p.sid.value, revision) { videoTrackOf(p) }
    Box(Modifier.fillMaxWidth().aspectRatio(0.8f).clip(RoundedCornerShape(16.dp)).background(Color.White.copy(alpha = 0.06f)),
        contentAlignment = Alignment.Center) {
        if (track != null) {
            key(track) {
                AndroidView(modifier = Modifier.fillMaxSize(),
                    factory = { c ->
                        TextureViewRenderer(c).also { v ->
                            room.initVideoRenderer(v)
                            v.setMirror(mirror)
                            track.addRenderer(v)
                        }
                    },
                    onRelease = { v ->
                        try { track.removeRenderer(v) } catch (_: Exception) {}
                        try { v.release() } catch (_: Exception) {}
                    })
            }
        } else {
            Box(Modifier.size(64.dp).clip(CircleShape).background(Color.White.copy(alpha = 0.12f)), contentAlignment = Alignment.Center) {
                Text(label.take(1).uppercase(), color = Color.White, fontSize = 26.sp, fontWeight = FontWeight.SemiBold)
            }
        }
        Text(label, color = Color.White, fontSize = 12.sp,
            modifier = Modifier.align(Alignment.BottomStart).padding(8.dp)
                .background(Color.Black.copy(alpha = 0.45f), RoundedCornerShape(8.dp)).padding(horizontal = 6.dp, vertical = 2.dp))
    }
}

/** Host-only: connect a LiveKit project so voice/video turns on for everyone. Transparent about what
 *  the relay can and can't see; the API secret is stored only on the skwod server. */
@Composable
fun VoiceSetupDialog(onClose: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var url by remember { mutableStateOf("") }
    var apiKey by remember { mutableStateOf("") }
    var apiSecret by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }

    Dialog(onDismissRequest = onClose) {
        Surface(color = Color(0xFF14141C), shape = RoundedCornerShape(20.dp)) {
            Column(
                Modifier.padding(20.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text("Turn on voice & video", color = Color.White, style = MaterialTheme.typography.titleMedium)
                Text(
                    "Calls run on LiveKit. As the host you connect your own project once, and everyone gets " +
                        "voice and video. Calls are end-to-end encrypted — the relay only ever forwards ciphertext; " +
                        "it can see metadata (who's in a call, when, IPs) but never the call itself. Your API secret " +
                        "is stored only on your Skwod server.",
                    color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    "Create a free project at cloud.livekit.io, then paste its URL, API Key, and API Secret.",
                    color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(url, { url = it; error = "" }, label = { Text("Project URL (wss://…)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(apiKey, { apiKey = it; error = "" }, label = { Text("API Key") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(
                    apiSecret, { apiSecret = it; error = "" }, label = { Text("API Secret") },
                    singleLine = true, visualTransformation = PasswordVisualTransformation(),
                    // Password keyboard: keeps the IME from learning/suggesting the LiveKit secret.
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (error.isNotEmpty()) Text(error, color = Color(0xFFF87171), style = MaterialTheme.typography.labelSmall)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = onClose) { Text("Cancel") }
                    Button(
                        onClick = {
                            if (busy) return@Button
                            busy = true; error = ""
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { model.client?.setVoiceConfig(url.trim(), apiKey.trim(), apiSecret.trim()) }
                                    onClose()
                                } catch (e: Exception) {
                                    error = "Couldn't save — check the URL, key, and secret."; busy = false
                                }
                            }
                        },
                        enabled = !busy && url.trim().startsWith("ws") && apiKey.isNotBlank() && apiSecret.isNotBlank(),
                    ) { Text("Turn on") }
                }
            }
        }
    }
}

/** Our key rotated but the sender could not be switched to it (see [SenderKeyIndex]). */
private class KeyRotationFailed : Exception()

/**
 * Sets the key index OUR outgoing frames are encrypted under.
 *
 * LiveKit Android 2.27 exposes no `setCurrentKeyIndex` on its key provider (the Apple SDK does):
 * `E2EEManager.addRtpSender` calls `FrameCryptor.setKeyIndex(keyProvider.getLatestKeyIndex(id))`
 * once, when a track is published, and never again. The sender `FrameCryptor`s live in
 * `E2EEManager.frameCryptors` (a private `Map<Pair<trackSid, Participant.Identity>, FrameCryptor>`),
 * so that map is reached by reflection; `proguard-rules.pro` keeps `io.livekit.android.**`
 * members, so the name survives R8. Verified against the 2.27.0 AAR.
 */
internal object SenderKeyIndex {
    private val field: java.lang.reflect.Field? by lazy {
        try {
            io.livekit.android.e2ee.E2EEManager::class.java.getDeclaredField("frameCryptors").apply { isAccessible = true }
        } catch (_: Throwable) { null }
    }

    /** True when every sender of `identity` now uses `index` (vacuously true before any track is
     *  published — a new sender picks up the latest registered index by itself). */
    fun apply(room: Room, identity: String, index: Int): Boolean {
        val manager = room.e2eeManager ?: return false
        val map = try { field?.get(manager) as? Map<*, *> } catch (_: Throwable) { null } ?: return false
        return try {
            var ok = true
            for ((key, cryptor) in map.entries.toList()) {
                val who = (key as? Pair<*, *>)?.second
                if (!ownedBy(who, identity)) continue
                val fc = cryptor as? livekit.org.webrtc.FrameCryptor
                if (fc == null) { ok = false; continue }
                if (fc.keyIndex != index) fc.keyIndex = index
            }
            ok
        } catch (_: Throwable) { false }
    }

    /** `who` is the boxed `Participant.Identity` of a frame-cryptor map key. */
    internal fun ownedBy(who: Any?, identity: String): Boolean =
        when (who) {
            is Participant.Identity -> who.value == identity
            is String -> who == identity
            else -> false
        }
}
