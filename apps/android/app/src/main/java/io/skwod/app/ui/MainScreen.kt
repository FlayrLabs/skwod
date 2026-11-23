package io.skwod.app

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import android.widget.Toast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The mobile shell: a two-page horizontal pager. Page 0 is the list (far-left skwod
 * rail + the server/channel drawer, with the floating you-bar); page 1 is the selected chat. Picking
 * a channel slides to the chat; swiping right returns to the list. No bottom nav — the rail is the
 * only global navigation, exactly like the reference app. Mobile is JOIN-only: hosting/creating is a
 * Mac capability, so the only in-app affordances are join-with-code and invite.
 */
@Composable
fun MainScreen(onSignOut: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val chat = model.chat
    val scope = rememberCoroutineScope()
    val pager = rememberPagerState(pageCount = { 2 })

    // On entering a workspace, load the sidebar, recover memberships (re-login/reinstall), and pick
    // up any channels the host added since we last synced.
    LaunchedEffect(model.current?.id) {
        chat.loadIfNeeded()
        launch { chat.recoverMemberships() }
        launch { chat.syncServerChannels() }
    }
    // Selection change drives the pager: a picked destination slides to the chat, home slides back.
    LaunchedEffect(chat.selection) {
        pager.animateScrollToPage(if (chat.selection == null) 0 else 1)
    }
    // And the pager drives notification focus: swiping back to the list means the chat is no
    // longer on screen, so its messages must notify again (selection stays for state, focus clears).
    LaunchedEffect(pager.settledPage) {
        if (pager.settledPage == 0) model.realtime.focusedTopic = null
        else model.realtime.focusedTopic = when (val sel = chat.selection) {
            is SidebarItem.Space -> "channel:${sel.space.channelId}"
            is SidebarItem.Dm -> "dm:${sel.dm.conversationId}"
            is SidebarItem.Group -> "dm:${sel.group.conversationId}"
            else -> null
        }
    }

    // Updates come from the public release feed, not from the connected skwod: the daily check
    // (Updater.autoCheck, started with the process and on every foreground) fills the banner below.
    // Signed up with an invite: its code also joins the invite's server (token invites join at
    // once, code invites wait for the host's approval). That is AppModel.joins' job now — it is
    // persisted and resumed at launch, so it no longer depends on this screen staying alive.
    // A tapped invite while signed in: open the connect form with it (it only ever prefills).
    var showInvite by remember { mutableStateOf(false) }
    LaunchedEffect(model.pendingInvite) { if (model.pendingInvite != null) showInvite = true }
    // Calls: a ring that was answered (notification or the in-app prompt) opens that server's room.
    var callServer by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(model.answeredCallServer) {
        model.answeredCallServer?.let { callServer = it; model.answeredCallServer = null }
    }
    val uiCtx = LocalContext.current

    // Three contrast steps over the shared glass backdrop: chrome (rail, darkest) →
    // drawer (+1 lift) → chat (lightest). All translucent washes, so the glow reads through.
    Box(Modifier.fillMaxSize()) {
        HorizontalPager(state = pager, modifier = Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.28f))) { page ->
            if (page == 0) {
                Box(Modifier.fillMaxSize()) {
                    Row(Modifier.fillMaxSize()) {
                        ServerRail(chat, onSignOut)
                        Box(Modifier.weight(1f).fillMaxHeight().background(Color.White.copy(alpha = 0.05f))) {
                            DrawerList(chat, onSignOut)
                            MobileYouBar(onSignOut, Modifier.align(Alignment.BottomCenter))
                        }
                    }
                }
            } else {
                Box(Modifier.fillMaxSize().background(Color.White.copy(alpha = 0.085f))) {
                    DrawerChat(chat)
                }
            }
        }
        Column(Modifier.align(Alignment.TopCenter).statusBarsPadding(), horizontalAlignment = Alignment.CenterHorizontally) {
            ConnectionBanner()
            HostNewerBanner()
            UpdateBanner()
        }
    }

    BatteryPromptOnce()
    model.incomingCall?.let { ring ->
        if (callServer == null) IncomingCallDialog(ring,
            onAnswer = { model.answerIncoming(ring) },
            onDecline = { Notifications.cancelIncomingCall(uiCtx); model.incomingCall = null })
    }
    callServer?.let { sid ->
        Dialog(onDismissRequest = {}, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            VoiceCallScreen(serverId = sid, onClose = { callServer = null; model.callOpening = false })
        }
    }
    // Calls ringing on more than one skwod at once: the user says which — never a value a
    // server reported (an `expires_at`, an ordering).
    if (model.ringChoices.isNotEmpty() && callServer == null) {
        AlertDialog(
            onDismissRequest = { model.ringChoices = emptyList() },
            confirmButton = {},
            dismissButton = { TextButton(onClick = { model.ringChoices = emptyList() }) { Text("Decline all") } },
            title = { Text("Who's calling?") },
            text = {
                Column {
                    Text("Calls are ringing on more than one of your Skwods. Pick the one to answer.",
                        color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    model.ringChoices.forEach { choice ->
                        Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable { model.answerChoice(choice) }
                            .padding(horizontal = 8.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Call, null, tint = Color(0xFF22C55E))
                            Spacer(Modifier.width(12.dp))
                            Text(choice.workspaceName, color = Color.White, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                            Text("Answer", color = SkAccent)
                        }
                    }
                }
            }
        )
    }
    if (showInvite) {
        Dialog(onDismissRequest = { showInvite = false; model.pendingInvite = null }) {
            Surface(color = GlassDialogTone, shape = RoundedCornerShape(20.dp)) {
                AuthScreen(onDone = { showInvite = false })
            }
        }
    }
}

/**
 * "A new version is available" strip shown at the top of the app when the release feed
 * advertises a newer build. One tap downloads the apk and launches Android's installer.
 */
@Composable
fun UpdateBanner(modifier: Modifier = Modifier) {
    val info = Updater.available ?: return
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    Surface(
        color = Color(0xFF1B1830).copy(alpha = 0.96f),
        shape = RoundedCornerShape(16.dp),
        shadowElevation = 8.dp,
        modifier = modifier.padding(horizontal = 12.dp, vertical = 8.dp).fillMaxWidth()
    ) {
        Row(Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.SystemUpdateAlt, null, tint = SkAccent)
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text("Update available — ${info.version} (${info.build})",
                    color = Color.White, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                val sub = when (val p = Updater.phase) {
                    is Updater.Phase.Downloading -> "Downloading… ${p.pct}%"
                    Updater.Phase.Installing -> "Opening installer…"
                    is Updater.Phase.Failed -> p.msg
                    else -> info.notes.ifEmpty { "" }
                }
                if (sub.isNotEmpty()) {
                    val err = Updater.phase is Updater.Phase.Failed
                    Text(sub, color = if (err) Color(0xFFF87171) else Color.White.copy(alpha = 0.6f),
                        style = MaterialTheme.typography.labelSmall, maxLines = 2)
                }
            }
            Spacer(Modifier.width(8.dp))
            when (Updater.phase) {
                is Updater.Phase.Downloading, Updater.Phase.Installing ->
                    CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp, color = SkAccent)
                else -> Button(onClick = { scope.launch { Updater.install(ctx) } },
                    colors = ButtonDefaults.buttonColors(containerColor = SkAccent)) { Text("Update") }
            }
        }
    }
}

/**
 * The active skwod's host refuses this app's version ([AppModel.hostNewer]): it stays on screen —
 * nothing was signed out — with "Update Skwod", which looks for the newer build on the release
 * feed ([Updater]) and installs it.
 */
@Composable
fun HostNewerBanner(modifier: Modifier = Modifier) {
    val model = AppModel.get(LocalContext.current)
    model.hostNewer ?: return
    // The regular banner takes over once the newer build is known.
    if (Updater.available != null) return
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var note by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    Surface(color = Color(0xFF2A1F0E).copy(alpha = 0.96f), shape = RoundedCornerShape(16.dp), shadowElevation = 8.dp,
        modifier = modifier.padding(horizontal = 12.dp, vertical = 8.dp).fillMaxWidth()) {
        Row(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.SystemUpdateAlt, null, tint = Color(0xFFFFA726))
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text("This Skwod's host is newer — update Skwod", color = Color.White,
                    style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                Text(note ?: "You're still signed in. Messages stay on this phone until the app is updated.",
                    color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.labelSmall, maxLines = 3)
            }
            Spacer(Modifier.width(8.dp))
            if (busy) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp, color = SkAccent)
            else Button(onClick = {
                busy = true; note = null
                scope.launch {
                    val found = Updater.available ?: Updater.check(manual = true)
                    if (found != null) Updater.install(ctx)
                    else note = "No newer Skwod is published yet. Try again later, or ask your host which version they run."
                    busy = false
                }
            }, colors = ButtonDefaults.buttonColors(containerColor = SkAccent)) { Text("Update Skwod") }
        }
    }
}

/** Far-left rail: Home/DMs (skwod icon), Feed, one tile per connected skwod, and a "+" menu. */
@Composable
private fun ServerRail(chat: AppChat, onSignOut: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var tick by remember { mutableStateOf(0) }
    var showAdd by remember { mutableStateOf(false) }
    var showCreate by remember { mutableStateOf(false) }
    // Long-press menus: a server's, a skwod's, and what they open.
    var serverMenuFor by remember { mutableStateOf<String?>(null) }
    var skwodMenuFor by remember { mutableStateOf<String?>(null) }
    var inviteFor by remember { mutableStateOf<RealSpace?>(null) }
    var rolesFor by remember { mutableStateOf<RealSpace?>(null) }
    var iconFor by remember { mutableStateOf<RealSpace?>(null) }
    var confirmSignOut by remember { mutableStateOf(false) }

    Column(
        // No backing of its own: the rail sits directly on the pager's dark chrome veil, exactly
        // like the macOS rail sits bare on the window chrome.
        Modifier.width(68.dp).fillMaxHeight().padding(top = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        RailTile(active = chat.homeMode, onClick = { chat.showHome() }) {
            // The skwod (squid) logo IS the home/DMs button — matches iOS.
            androidx.compose.foundation.Image(rememberAppLogo(), "Home", Modifier.fillMaxSize())
        }
        Spacer(Modifier.height(8.dp))
        RailTile(active = chat.selection is SidebarItem.Feed, onClick = { chat.homeMode = false; chat.selection = SidebarItem.Feed }) {
            Box(Modifier.fillMaxSize().background(Color.White.copy(alpha = 0.06f)), contentAlignment = Alignment.Center) {
                Icon(Icons.Filled.Newspaper, "Feed", tint = Color.White.copy(alpha = 0.85f))
            }
        }
        Spacer(Modifier.height(8.dp))
        Box(Modifier.width(32.dp).height(2.dp).background(Color.White.copy(alpha = 0.12f)))
        Spacer(Modifier.height(8.dp))

        key(tick) {
            // SERVERS (top): one tile per server (guild) inside the CURRENT skwod. Tapping shows its
            // channels in the middle column. A "+" creates a server here.
            chat.serverGroups().forEach { g ->
                RailTile(active = chat.isServerActive(g), onClick = { chat.openServer(g); tick++ },
                    onLongClick = { serverMenuFor = g.serverId }) {
                    Box(Modifier.fillMaxSize()) {
                        AvatarTile(AvatarStore.serverKey(g.serverId), g.name, size = 44, corner = 14)
                        MentionBadge(model.mentionCount(g.channels.map { "channel:${it.channelId}" }), Modifier.align(Alignment.BottomEnd))
                    }
                    ServerActionsMenu(serverMenuFor == g.serverId, g, onDismiss = { serverMenuFor = null },
                        onInvite = { inviteFor = g.channels.firstOrNull() }, onIcon = { iconFor = g.channels.firstOrNull() },
                        onPermissions = { rolesFor = g.channels.firstOrNull() })
                }
                Spacer(Modifier.height(8.dp))
            }
            if (model.canCreateServers) {
                RailTile(active = false, onClick = { showCreate = true }) {
                    Box(Modifier.fillMaxSize().background(Color.White.copy(alpha = 0.06f)), contentAlignment = Alignment.Center) {
                        Icon(Icons.Filled.Add, "Create a server", tint = SkAccent)
                    }
                }
                Spacer(Modifier.height(8.dp))
            }

            Box(Modifier.width(32.dp).height(2.dp).background(Color.White.copy(alpha = 0.12f)))
            Spacer(Modifier.height(8.dp))

            // SKWODS (bottom): one tile per connected skwod (host). Tapping switches host; the servers
            // above update to that skwod's servers.
            model.workspaces.forEach { w ->
                val active = w.id == model.current?.id && !chat.homeMode
                val label = WorkspaceLabel.of(w, model.workspaces)
                RailTile(active = active, onLongClick = { skwodMenuFor = w.localId }, onClick = {
                    // The skwod already open stays open (no teardown, no login flash); one whose
                    // session is over opens its login without leaving the one in use.
                    if (!w.isSignedOut || w.id == model.current?.id) { chat.homeMode = false; chat.selection = null; chat.railServerId = null }
                    scope.launch { withContext(Dispatchers.IO) { model.tapSkwod(w) }; tick++ }
                }) {
                    Box(Modifier.fillMaxSize().semantics { contentDescription = listOfNotNull(label, WorkspaceLabel.state(w)).joinToString(". ") }) {
                        AvatarTile(w.instanceId?.let { AvatarStore.skwodKey(it) }, w.displayName, size = 44, corner = 14)
                        if (w.isSignedOut) Box(Modifier.align(Alignment.BottomEnd).size(16.dp).background(Color.Black.copy(alpha = 0.75f), CircleShape),
                            contentAlignment = Alignment.Center) {
                            Icon(Icons.Filled.Lock, null, tint = Color.White, modifier = Modifier.size(10.dp))
                        }
                    }
                    SkwodActionsMenu(skwodMenuFor == w.localId, w, onDismiss = { skwodMenuFor = null },
                        onOpen = { scope.launch { withContext(Dispatchers.IO) { model.tapSkwod(w) }; tick++ } },
                        onSignOut = { confirmSignOut = true },
                        onRemoved = { tick++; onSignOut() })
                }
                Spacer(Modifier.height(8.dp))
            }
            RailTile(active = false, onClick = { showAdd = true }) {
                Box(Modifier.fillMaxSize().background(Color.White.copy(alpha = 0.06f)), contentAlignment = Alignment.Center) {
                    Icon(Icons.Filled.Layers, "Join or host a Skwod", tint = SkAccent)
                }
            }
        }
    }

    if (showAdd) {
        Dialog(onDismissRequest = { showAdd = false }) {
            Surface(color = GlassDialogTone, shape = RoundedCornerShape(20.dp)) {
                AuthScreen(onDone = { showAdd = false })
            }
        }
    }
    if (showCreate) {
        CreateServerDialog(onCancel = { showCreate = false }, onCreate = { chat.addSpace(it); showCreate = false })
    }
    inviteFor?.let { sp ->
        Dialog(onDismissRequest = { inviteFor = null }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            Surface(color = GlassDialogTone) { SecureJoinScreen(sp, onClose = { inviteFor = null }) }
        }
    }
    rolesFor?.let { sp ->
        Dialog(onDismissRequest = { rolesFor = null }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            Surface(color = GlassDialogTone) { RolesSheet(sp.serverId, sp.name, onClose = { rolesFor = null }) }
        }
    }
    iconFor?.let { sp ->
        AvatarPickerDialog(
            title = "Server icon", currentKey = AvatarStore.serverKey(sp.serverId), name = sp.name,
            onPick = { model.avatars.setServerAvatar(sp.serverId, it) },
            onRemove = { model.avatars.clearAvatar(AvatarStore.serverKey(sp.serverId), chat.spaces.filter { it.serverId == sp.serverId }.map { it.channelId }) },
            onClose = { iconFor = null })
    }
    if (confirmSignOut) {
        val name = model.current?.displayName ?: "this Skwod"
        AlertDialog(
            onDismissRequest = { confirmSignOut = false },
            confirmButton = {
                TextButton(onClick = {
                    confirmSignOut = false
                    scope.launch { withContext(Dispatchers.IO) { model.leaveCurrent() }; tick++; onSignOut() }
                }) { Text("Sign out") }
            },
            dismissButton = { TextButton(onClick = { confirmSignOut = false }) { Text("Cancel") } },
            title = { Text("Sign out of $name?") },
            text = { Text("Your messages and keys stay on this device, locked. Sign in again with your password to carry on where you left off — no relinking.") }
        )
    }
}

@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
private fun RailTile(active: Boolean, onClick: () -> Unit, onLongClick: (() -> Unit)? = null, content: @Composable () -> Unit) {
    Row(Modifier.fillMaxWidth().height(52.dp), verticalAlignment = Alignment.CenterVertically) {
        // Selection pill hugging the left edge.
        Box(Modifier.width(4.dp).height(if (active) 40.dp else 0.dp).clip(RoundedCornerShape(50)).background(Color.White))
        Spacer(Modifier.weight(1f))
        Box(Modifier.size(48.dp).clip(RoundedCornerShape(16.dp)).combinedClickable(onClick = onClick, onLongClick = onLongClick)) { content() }
        Spacer(Modifier.weight(1f))
    }
}

/** Page 0's content pane: the server/channel drawer, or the DMs home when the skwod icon is active. */
@Composable
private fun DrawerList(chat: AppChat, onSignOut: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val drawerScope = rememberCoroutineScope()
    var menu by remember { mutableStateOf(false) }
    var showJoin by remember { mutableStateOf(false) }
    var showCreate by remember { mutableStateOf(false) }
    var inviteFor by remember { mutableStateOf<RealSpace?>(null) }
    var showSettings by remember { mutableStateOf(false) }
    var rolesFor by remember { mutableStateOf<RealSpace?>(null) }
    var serverIconFor by remember { mutableStateOf<RealSpace?>(null) }
    var showReports by remember { mutableStateOf(false) }
    var serverMenuFor by remember { mutableStateOf<String?>(null) }
    var query by remember { mutableStateOf("") }
    // Voice/video: the server whose call is open, the host setup dialog, and an in-flight check.
    var voiceCallServer by remember { mutableStateOf<String?>(null) }
    var showVoiceSetup by remember { mutableStateOf(false) }
    var voiceChecking by remember { mutableStateOf(false) }
    val voiceCtx = LocalContext.current

    // The space to invite into / manage: the selected one, else the first.
    val inviteSpace = (chat.selection as? SidebarItem.Space)?.space ?: chat.spaces.firstOrNull()

    inviteFor?.let { sp ->
        SecureJoinScreen(sp, onClose = { inviteFor = null })
        return
    }
    if (showSettings) {
        SkwodSettingsSheet(onClose = { showSettings = false }, onSignOut = onSignOut)
        return
    }
    rolesFor?.let { sp ->
        RolesSheet(sp.serverId, sp.name, onClose = { rolesFor = null })
        return
    }

    if (chat.homeMode) {
        DmHomeView(chat)
    } else {
        Column(Modifier.fillMaxSize().padding(horizontal = 8.dp)) {
            Spacer(Modifier.height(10.dp))
            // Header: a back-to-servers arrow when inside a server, then a "Name ›" dropdown (server
            // name in a server, skwod name in the overview). Pinned above the scroll, bare on the
            // drawer's glass — same color as the panel it heads.
            Box {
                Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    if (chat.inChannelsMode) {
                        IconButton(onClick = { chat.showServerBoxes(null) }, modifier = Modifier.size(28.dp)) {
                            Icon(Icons.Filled.ChevronLeft, "Back to servers", tint = Color.White.copy(alpha = 0.85f))
                        }
                        Spacer(Modifier.width(4.dp))
                    }
                    Row(Modifier.clickable { menu = true }, verticalAlignment = Alignment.CenterVertically) {
                        // Unread reports show on the menu they are in.
                        if (model.reports.list.isNotEmpty()) { ReportsBadge(model.reports.list.size); Spacer(Modifier.width(6.dp)) }
                        Text(if (chat.inChannelsMode) (chat.currentServer()?.name ?: model.current?.displayName ?: "Skwod")
                             else SkwodMenu.heading(model.current?.displayName ?: "Skwod"), color = Color.White,
                            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.width(6.dp))
                        Icon(Icons.Filled.ChevronRight, null, tint = Color.White.copy(alpha = 0.5f))
                    }
                }
                if (chat.inChannelsMode) chat.currentServer()?.let { g ->
                    ServerActionsMenu(serverMenuFor == g.serverId, g, onDismiss = { serverMenuFor = null },
                        onInvite = { inviteFor = g.channels.firstOrNull() }, onIcon = { serverIconFor = g.channels.firstOrNull() },
                        onPermissions = { rolesFor = g.channels.firstOrNull() })
                }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    if (inviteSpace != null) DropdownMenuItem(text = { Text("Invite people") },
                        onClick = { menu = false; inviteFor = inviteSpace },
                        leadingIcon = { Icon(Icons.Filled.PersonAdd, null) })
                    DropdownMenuItem(text = { Text("Skwod settings") },
                        onClick = { menu = false; showSettings = true }, leadingIcon = { Icon(Icons.Filled.Settings, null) })
                    if (inviteSpace != null) DropdownMenuItem(text = { Text("Manage permissions") },
                        onClick = { menu = false; rolesFor = inviteSpace }, leadingIcon = { Icon(Icons.Filled.Shield, null) })
                    if (inviteSpace != null) DropdownMenuItem(text = { Text("Change server icon") },
                        onClick = { menu = false; serverIconFor = inviteSpace }, leadingIcon = { Icon(Icons.Filled.Image, null) })
                    // The owner's reports inbox: there when something was reported, and always for the host.
                    if (ReportRules.entryVisible(model.reports.list.size, model.isInstanceOwner)) DropdownMenuItem(text = { Text("Reports") },
                        onClick = { menu = false; showReports = true }, leadingIcon = { Icon(Icons.Filled.Flag, null) },
                        trailingIcon = { ReportsBadge(model.reports.list.size) })
                    // Inside a server: its own menu (mute, leave — or delete, for its owner).
                    if (chat.inChannelsMode) chat.currentServer()?.let { g ->
                        DropdownMenuItem(text = { Text("Server options…") },
                            onClick = { menu = false; serverMenuFor = g.serverId }, leadingIcon = { Icon(Icons.Filled.MoreHoriz, null) })
                    }
                    HorizontalDivider()
                    if (model.canCreateServers) DropdownMenuItem(text = { Text("Create a server") },
                        onClick = { menu = false; showCreate = true }, leadingIcon = { Icon(Icons.Filled.Add, null) })
                    DropdownMenuItem(text = { Text("Join with a code") },
                        onClick = { menu = false; showJoin = true }, leadingIcon = { Icon(Icons.Filled.ConfirmationNumber, null) })
                }
            }
            Spacer(Modifier.height(10.dp))
            // A join in flight (or one that hit a problem) is never invisible: what it is
            // waiting for is said here until the server's channels appear.
            model.joins.status?.let { st ->
                val tone = if (st.problem) Color(0xFFFFA726) else Color.White
                Row(Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp)
                    .clip(RoundedCornerShape(12.dp)).background(tone.copy(alpha = 0.10f)).padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    if (st.problem) Icon(Icons.Filled.Info, null, tint = tone, modifier = Modifier.size(16.dp))
                    else CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp, color = Color.White)
                    Spacer(Modifier.width(8.dp))
                    Text(st.text, color = tone.copy(alpha = 0.9f), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                    if (st.problem) IconButton(onClick = { model.joins.status = null }, modifier = Modifier.size(22.dp)) {
                        Icon(Icons.Filled.Close, "Dismiss", tint = tone.copy(alpha = 0.7f), modifier = Modifier.size(14.dp))
                    }
                }
                Spacer(Modifier.height(6.dp))
            }
            Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            // Search + invite.
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 4.dp)) {
                OutlinedTextField(query, { query = it }, placeholder = { Text("Search") }, singleLine = true,
                    leadingIcon = { Icon(Icons.Filled.Search, null) }, modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(50))
                Spacer(Modifier.width(8.dp))
                IconButton(onClick = { inviteSpace?.let { inviteFor = it } }, enabled = inviteSpace != null) {
                    Icon(Icons.Filled.PersonAdd, "Invite", tint = Color.White.copy(alpha = 0.8f))
                }
            }
            Spacer(Modifier.height(12.dp))

            if (chat.spaces.isEmpty()) {
                if (chat.provisioning) {
                    Row(verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
                        CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp, color = Color.White)
                        Spacer(Modifier.width(8.dp))
                        Text("Setting up your channels…", color = Color.White.copy(alpha = 0.55f),
                            style = MaterialTheme.typography.bodySmall)
                    }
                } else {
                    // No servers yet: give a real call-to-action, not just dead-end text — the join
                    // action was otherwise buried in the header dropdown.
                    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                        horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Filled.Groups, null, tint = Color.White.copy(alpha = 0.4f), modifier = Modifier.size(40.dp))
                        Spacer(Modifier.height(10.dp))
                        Text("No servers yet", color = Color.White, style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(4.dp))
                        Text("Join one with an invite code from a friend who hosts a Skwod.",
                            color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.bodySmall,
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center)
                        Spacer(Modifier.height(14.dp))
                        Button(onClick = { showJoin = true },
                            colors = ButtonDefaults.buttonColors(containerColor = Color.White, contentColor = Color.Black)) {
                            Icon(Icons.Filled.ConfirmationNumber, null); Spacer(Modifier.width(6.dp))
                            Text("Join with a code", fontWeight = FontWeight.SemiBold)
                        }
                        if (model.canCreateServers) {
                            Spacer(Modifier.height(8.dp))
                            OutlinedButton(onClick = { showCreate = true }) {
                                Icon(Icons.Filled.Add, null); Spacer(Modifier.width(6.dp)); Text("Create a server")
                            }
                        }
                    }
                }
            } else if (chat.inChannelsMode) {
                // Inside a server: its channels.
                chat.currentServer()?.let { group ->
                    Text(group.name.uppercase(), color = Color.White.copy(alpha = 0.55f),
                        style = MaterialTheme.typography.labelMedium,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp))
                    val q = query.trim()
                    val channels = if (q.isEmpty()) group.channels
                        else group.channels.filter { it.channelName.contains(q, ignoreCase = true) }
                    channels.forEach { s ->
                        ChannelRow(model, "channel:${s.channelId}", s.channelName,
                            selected = chat.highlightedChannelId == s.channelId,
                            onClick = { chat.openChannel(s) },
                            onRemove = { chat.removeSpace(s) },
                            onClear = {
                                drawerScope.launch {
                                    try { withContext(Dispatchers.IO) { model.client?.clearChannelMessages(s.channelId) } } catch (_: Exception) {}
                                }
                            })
                    }

                    // Voice Channels — one E2EE room for the skwod. Gated on the host wiring LiveKit.
                    Spacer(Modifier.height(6.dp))
                    Text("VOICE CHANNELS", color = Color.White.copy(alpha = 0.55f),
                        style = MaterialTheme.typography.labelMedium,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp))
                    val voiceServerId = group.serverId
                    Row(
                        Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 2.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .clickable {
                                if (voiceChecking) return@clickable
                                voiceChecking = true
                                drawerScope.launch {
                                    val cfg = try { withContext(Dispatchers.IO) { model.client?.voiceConfig() } } catch (_: Exception) { null }
                                    voiceChecking = false
                                    if (cfg?.configured == true) {
                                        voiceCallServer = voiceServerId
                                    } else {
                                        val owner = withContext(Dispatchers.IO) { model.listAccounts() != null }
                                        if (owner) showVoiceSetup = true
                                        else Toast.makeText(voiceCtx, "Voice isn't set up yet — ask the host to turn it on.", Toast.LENGTH_SHORT).show()
                                    }
                                }
                            }
                            .padding(horizontal = 14.dp, vertical = 13.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Filled.VolumeUp, null, tint = Color.White.copy(alpha = 0.6f))
                        Spacer(Modifier.width(12.dp))
                        Text("General", color = Color.White.copy(alpha = 0.8f))
                    }
                }
            } else {
                // Skwod overview: the list of servers. Tapping one opens its channels.
                Text("SERVERS", color = Color.White.copy(alpha = 0.55f),
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp))
                chat.serverGroups().forEach { g ->
                    Box {
                        ServerRow(g.name, g.channels.size, onClick = { chat.openServer(g) }, onLongClick = { serverMenuFor = g.serverId })
                        MentionBadge(model.mentionCount(g.channels.map { "channel:${it.channelId}" }), Modifier.align(Alignment.CenterEnd).padding(end = 36.dp))
                        ServerActionsMenu(serverMenuFor == g.serverId, g, onDismiss = { serverMenuFor = null },
                            onInvite = { inviteFor = g.channels.firstOrNull() }, onIcon = { serverIconFor = g.channels.firstOrNull() },
                            onPermissions = { rolesFor = g.channels.firstOrNull() })
                    }
                }
            }
            Spacer(Modifier.height(96.dp)) // clearance for the floating you-bar
            }
        }
    }

    if (showJoin) JoinWithCodeDialog(chat, onClose = { showJoin = false })
    if (showReports) ReportsDialog { showReports = false }
    if (showCreate) CreateServerDialog(onCancel = { showCreate = false }, onCreate = { chat.addSpace(it); showCreate = false })
    voiceCallServer?.let { sid ->
        Dialog(onDismissRequest = { voiceCallServer = null }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            VoiceCallScreen(serverId = sid, onClose = { voiceCallServer = null })
        }
    }
    if (showVoiceSetup) VoiceSetupDialog(onClose = { showVoiceSetup = false })
    serverIconFor?.let { sp ->
        AvatarPickerDialog(
            title = "Server icon",
            currentKey = AvatarStore.serverKey(sp.serverId),
            name = sp.name,
            onPick = { model.avatars.setServerAvatar(sp.serverId, it) },
            onRemove = {
                model.avatars.clearAvatar(AvatarStore.serverKey(sp.serverId),
                    chat.spaces.filter { it.serverId == sp.serverId }.map { it.channelId })
            },
            onClose = { serverIconFor = null }
        )
    }
}

@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
private fun ChannelRow(model: AppModel, muteKey: String, name: String, selected: Boolean, onClick: () -> Unit, onRemove: () -> Unit, onClear: () -> Unit) {
    var menu by remember { mutableStateOf(false) }
    var muting by remember { mutableStateOf(false) }
    var confirmClear by remember { mutableStateOf(false) }
    Box {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 2.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(if (selected) Color.White.copy(alpha = 0.11f) else Color.White.copy(alpha = 0.045f))
                .combinedClickable(onClick = onClick, onLongClick = { menu = true })
                .padding(horizontal = 14.dp, vertical = 13.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Filled.Tag, null, tint = if (selected) Color.White else Color.White.copy(alpha = 0.5f))
            Spacer(Modifier.width(12.dp))
            Text(name, color = if (selected) Color.White else Color.White.copy(alpha = 0.8f),
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
            Spacer(Modifier.weight(1f))
            MentionBadge(model.mentionCount(listOf(muteKey)))
            MutedMark(model, muteKey)
        }
        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
            MuteMenuItem(model, muteKey, onPick = { muting = true }, onDone = { menu = false })
            DropdownMenuItem(text = { Text("Clear all messages") }, onClick = { menu = false; confirmClear = true },
                leadingIcon = { Icon(Icons.Filled.ClearAll, null, tint = Color(0xFFF87171)) })
            DropdownMenuItem(text = { Text("Remove from list") }, onClick = { menu = false; onRemove() },
                leadingIcon = { Icon(Icons.Filled.VisibilityOff, null) })
        }
    }
    if (muting) MuteDialog(model, muteKey) { muting = false }
    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            confirmButton = {
                TextButton(onClick = { confirmClear = false; onClear() }) {
                    Text("Clear messages", color = Color(0xFFF87171))
                }
            },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text("Cancel") } },
            title = { Text("Clear all messages in #$name?") },
            text = { Text("Permanently deletes every message in this channel, for everyone. Members, roles, and the channel itself stay. This can't be undone.") }
        )
    }
}

/** A server row in the mobile skwod overview: monogram + name + channel count. Tapping opens it. */
@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
private fun ServerRow(name: String, channels: Int, onClick: () -> Unit, onLongClick: (() -> Unit)? = null) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 2.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(Color.White.copy(alpha = 0.045f))
            .combinedClickable(onClick = onClick, onLongClick = onLongClick)
            .padding(horizontal = 14.dp, vertical = 11.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(36.dp).clip(RoundedCornerShape(10.dp)).background(seededColor(name)),
            contentAlignment = Alignment.Center) {
            Text(name.firstOrNull()?.uppercaseChar()?.toString() ?: "?", color = Color.White, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(name, color = Color.White, fontWeight = FontWeight.SemiBold)
            Text("$channels channel${if (channels == 1) "" else "s"}",
                color = Color.White.copy(alpha = 0.5f), style = MaterialTheme.typography.bodySmall)
        }
        Icon(Icons.Filled.ChevronRight, null, tint = Color.White.copy(alpha = 0.35f))
    }
}

/** The floating user pill: avatar + presence, name + status, and a menu. */
@Composable
private fun MobileYouBar(onSignOut: () -> Unit, modifier: Modifier = Modifier) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var menu by remember { mutableStateOf(false) }
    var showProfile by remember { mutableStateOf(false) }
    var mutingSkwod by remember { mutableStateOf(false) }
    if (mutingSkwod) MuteDialog(model, MuteList.SKWOD) { mutingSkwod = false }
    var status by remember { mutableStateOf(model.myStatus) }
    // My real username on this skwod: stored at login, else resolved from a member list, else the
    // userId prefix as a last resort (never leaves the raw UUID showing when a name is available).
    var myName by remember(model.current?.id) { mutableStateOf(model.current?.username ?: "You") }
    LaunchedEffect(model.current?.id) {
        if (model.current?.username == null) model.resolveMyUsername()?.let { myName = it }
    }
    // Presence is heartbeated by the app-level background loop (AppModel.startBackgroundSync), which
    // keeps running no matter which screen is shown — so opening a chat no longer flips us offline.

    Box(modifier.padding(horizontal = 10.dp, vertical = 8.dp)) {
        Surface(color = GlassCardTone.copy(alpha = 0.95f), shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth().clickable { menu = true }) {
            Row(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                Box {
                    AvatarImage(model.session?.userId?.let { AvatarStore.userKey(it) }, myName, size = 36)
                    Box(Modifier.align(Alignment.BottomEnd).size(11.dp).clip(RoundedCornerShape(50))
                        .background(presenceColor(status)))
                }
                Spacer(Modifier.width(10.dp))
                Column {
                    Text(myName, color = Color.White, fontWeight = FontWeight.SemiBold)
                    Text(presenceLabel(status), color = presenceColor(status), style = MaterialTheme.typography.labelSmall)
                }
                Spacer(Modifier.weight(1f))
                // How we're connected, honestly and simply: directly, through a relay, or not at all.
                ConnectionPill()
            }
        }
        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
            // Server-accepted values only; "offline" is presented as "Invisible" (matches iOS).
            listOf("online" to "Online", "idle" to "Idle", "dnd" to "Do Not Disturb", "offline" to "Invisible").forEach { (key, label) ->
                DropdownMenuItem(text = { Text(label) }, onClick = {
                    status = key; model.myStatus = key; menu = false
                }, leadingIcon = {
                    Box(Modifier.size(12.dp).clip(RoundedCornerShape(50)).background(presenceColor(key)))
                })
            }
            HorizontalDivider()
            // The whole skwod: every conversation, and its calls.
            MuteMenuItem(model, MuteList.SKWOD, onPick = { mutingSkwod = true }, onDone = { menu = false })
            DropdownMenuItem(text = { Text("Profile & Skwods") }, onClick = { menu = false; showProfile = true },
                leadingIcon = { Icon(Icons.Filled.AccountCircle, null) })
        }
    }

    if (showProfile) {
        Dialog(onDismissRequest = { showProfile = false }) {
            Surface(color = GlassDialogTone, shape = RoundedCornerShape(20.dp)) {
                ProfileScreen(onSignOut = { showProfile = false; onSignOut() })
            }
        }
    }
}

/** Page 1: the selected chat/DM/home/feed. */
@Composable
private fun DrawerChat(chat: AppChat) {
    when (val sel = chat.selection) {
        is SidebarItem.Home -> DmHomeView(chat)
        is SidebarItem.Feed -> FeedView(chat)
        // Keyed by conversation: switching chats starts a fresh composition, so nothing waiting
        // in one composer (a pasted picture, a paste still being read) follows into the next.
        is SidebarItem.Space -> key("channel:" + sel.space.channelId) { ChannelView(sel.space, onBack = { chat.selection = null }) }
        is SidebarItem.Dm -> key("dm:" + sel.dm.conversationId) { DmChatView(sel.dm, onBack = { chat.selection = null }) }
        is SidebarItem.Group -> key("group:" + sel.group.conversationId) { GroupChatView(sel.group, onBack = { chat.selection = null }) }
        null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("Pick a channel", color = Color.White.copy(alpha = 0.5f))
        }
    }
}

@Composable
private fun JoinWithCodeDialog(chat: AppChat, onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    var code by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        confirmButton = {
            TextButton(onClick = {
                if (busy) return@TextButton
                busy = true; error = null
                scope.launch {
                    // A full invite link works too (any spelling, share links included): its code is
                    // used. A typed code is tidied up (case, spaces, dashes) — never while typing.
                    val c = InviteBeacon.strip(JoinCode.extract(code))
                    val err = chat.joinByCode(c)
                    busy = false
                    if (err == null) onClose() else error = err
                }
            }, enabled = !busy && code.isNotBlank()) { Text(if (busy) "…" else "Join") }
        },
        dismissButton = { TextButton(onClick = onClose, enabled = !busy) { Text("Cancel") } },
        title = { Text("Join with a code") },
        text = {
            Column {
                Text("Paste an invite code or link from a host.", color = Color.White.copy(alpha = 0.55f),
                    style = MaterialTheme.typography.labelSmall)
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(code, { code = it }, label = { Text("Invite code or link") }, singleLine = true)
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        }
    )
}

@Composable
fun ProfileScreen(onSignOut: () -> Unit) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    var tick by remember { mutableStateOf(0) }
    var showAdd by remember { mutableStateOf(false) }
    var game by remember { mutableStateOf<String?>(null) }
    var confirmDeleteAll by remember { mutableStateOf(false) }
    var deleteError by remember { mutableStateOf<String?>(null) }
    var showProfilePicker by remember { mutableStateOf(false) }
    var showSkwodIconPicker by remember { mutableStateOf(false) }
    var confirmSignOut by remember { mutableStateOf<String?>(null) }
    var showErase by remember { mutableStateOf(false) }
    var isOwner by remember { mutableStateOf(model.isInstanceOwner) }
    LaunchedEffect(model.current?.id) { isOwner = model.isInstanceOwner }

    when (game) {
        "whiteboard" -> { WhiteboardScreen(); return }
        "chess" -> { ChessScreen(); return }
    }

    val myUserId = model.session?.userId
    // Avatar pickers REPLACE the profile content (no Dialog-inside-a-Dialog, which won't show).
    if (showProfilePicker && myUserId != null) {
        AvatarPickerDialog(
            title = "Profile photo",
            currentKey = AvatarStore.userKey(myUserId),
            name = model.current?.username ?: myUserId.take(8),
            onPick = { model.avatars.setUserAvatar(it) },
            onRemove = { model.avatars.clearAvatar(AvatarStore.userKey(myUserId), model.chat.spaces.map { it.channelId }) },
            onClose = { showProfilePicker = false }
        )
        return
    }
    if (showSkwodIconPicker) {
        model.current?.instanceId?.let { iid ->
            AvatarPickerDialog(
                title = "Skwod icon",
                currentKey = AvatarStore.skwodKey(iid),
                name = model.current?.displayName ?: "Skwod",
                onPick = { model.avatars.setSkwodAvatar(iid, it) },
                onRemove = { model.avatars.clearAvatar(AvatarStore.skwodKey(iid), model.chat.spaces.map { it.channelId }) },
                onClose = { showSkwodIconPicker = false }
            )
            return
        }
    }
    Column(Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState())) {
        // Tappable profile picture (E2EE — visible only to members who share a server with you).
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.clickable { showProfilePicker = true }) {
                AvatarImage(myUserId?.let { AvatarStore.userKey(it) }, myUserId?.take(8) ?: "You", size = 64)
            }
            Spacer(Modifier.width(14.dp))
            Column {
                ScreenTitle("You", subtitle = model.current?.displayName ?: myUserId?.take(8)?.plus("…"))
                Text("Tap photo to change", color = SkAccent, style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier.clickable { showProfilePicker = true })
            }
        }
        Spacer(Modifier.height(20.dp))

        Text("Your Skwods", color = Color.White, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        key(tick) {
            model.workspaces.forEach { w ->
                Surface(color = GlassCardTone, shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).clickable {
                        scope.launch { withContext(Dispatchers.IO) { model.tapSkwod(w) }; tick++ }
                    }) {
                    Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                        Monogram(w.displayName, size = 32); Spacer(Modifier.width(12.dp))
                        Column {
                            Text(WorkspaceLabel.of(w, model.workspaces), color = Color.White)
                            WorkspaceLabel.state(w)?.let { Text(it, color = Color(0xFFFFA726), style = MaterialTheme.typography.labelSmall) }
                            // A p2p skwod's address is its host's key; show the short form, never a URL.
                            Text(w.nodeId?.let { "Host key ${InviteLink.shortKey(it)}" } ?: w.server,
                                color = Color.White.copy(alpha = 0.45f), style = MaterialTheme.typography.labelSmall)
                        }
                        Spacer(Modifier.weight(1f))
                        if (w.id == model.current?.id) Icon(Icons.Filled.CheckCircle, null, tint = SkAccent)
                    }
                }
            }
        }
        Spacer(Modifier.height(10.dp))
        // (Leaving a skwod is signing out of it now — at the bottom of this screen. It no
        // longer deletes anything from this phone.)
        OutlinedButton(onClick = { showAdd = true }) { Icon(Icons.Filled.Add, null); Spacer(Modifier.width(6.dp)); Text("Add a Skwod") }

        Spacer(Modifier.height(24.dp))
        Text("Games", color = Color.White, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        PlayCard("Whiteboard", "Sketch with friends", Icons.Filled.Brush) { game = "whiteboard" }
        PlayCard("Chess", "Pass-and-play 8×8", Icons.Filled.GridOn) { game = "chess" }

        Spacer(Modifier.height(24.dp))
        var showLicenses by remember { mutableStateOf(false) }
        PrivacySection()
        Spacer(Modifier.height(24.dp))
        EncryptionSection()
        Spacer(Modifier.height(24.dp))
        OutlinedButton(onClick = { showLicenses = true }, modifier = Modifier.fillMaxWidth()) { Text("Licenses & acknowledgements") }
        if (showLicenses) LicensesDialog { showLicenses = false }
        Spacer(Modifier.height(10.dp))
        val skwodName = model.current?.displayName ?: "this Skwod"
        OutlinedButton(onClick = { confirmSignOut = "one" }, modifier = Modifier.fillMaxWidth()) { Text("Sign out of $skwodName") }
        if (model.workspaces.count { !it.isSignedOut } > 1) {
            Spacer(Modifier.height(10.dp))
            OutlinedButton(onClick = { confirmSignOut = "all" }, modifier = Modifier.fillMaxWidth()) { Text("Sign out of all Skwods") }
        }
        Spacer(Modifier.height(10.dp))
        OutlinedButton(onClick = { showErase = true }, modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFF87171))) { Text("Erase this device…") }
        Spacer(Modifier.height(10.dp))
        OutlinedButton(onClick = { confirmDeleteAll = true }, modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFF87171))) {
            Text("Delete my account & all data")
        }
        deleteError?.let { Text(it, color = Color(0xFFF87171), style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 6.dp)) }

        // Skwod icon — the instance owner (host) can set it.
        if (isOwner && model.current?.instanceId != null) {
            Spacer(Modifier.height(20.dp))
            Text("Skwod icon", color = Color.White, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.clickable { showSkwodIconPicker = true }) {
                AvatarTile(model.current?.instanceId?.let { AvatarStore.skwodKey(it) },
                    model.current?.displayName ?: "Skwod", size = 52, corner = 16)
                Spacer(Modifier.width(12.dp))
                Text("Change Skwod icon", color = SkAccent, style = MaterialTheme.typography.bodyMedium)
            }
        }

        Spacer(Modifier.height(20.dp))
        // Build identity — confirm exactly which build is running. versionName (build) mirrors iOS.
        Text("Skwod ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
            color = Color.White.copy(alpha = 0.4f), style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
            textAlign = androidx.compose.ui.text.style.TextAlign.Center)

        // Manual update check — works whether or not the automatic daily one is switched on.
        val updateCtx = LocalContext.current
        val updateInfo = Updater.available
        UpdateSettingRow()
        TextButton(
            onClick = {
                if (updateInfo != null) scope.launch { Updater.install(updateCtx) }
                else scope.launch { Updater.check(manual = true) }
            },
            enabled = Updater.phase !is Updater.Phase.Checking,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                when {
                    updateInfo != null -> "Update to ${updateInfo.version} (${updateInfo.build})"
                    Updater.phase is Updater.Phase.Checking -> "Checking…"
                    Updater.lastCheckManual -> "Up to date"
                    else -> "Check for updates"
                },
                color = SkAccent
            )
        }
    }

    if (confirmDeleteAll) {
        AlertDialog(
            onDismissRequest = { confirmDeleteAll = false },
            confirmButton = {
                TextButton(onClick = {
                    confirmDeleteAll = false
                    scope.launch {
                        val err = withContext(Dispatchers.IO) { model.deleteMyAccount() }
                        if (err == null) { tick++; onSignOut() } else deleteError = err
                    }
                }) { Text("Delete everything", color = Color(0xFFF87171)) }
            },
            dismissButton = { TextButton(onClick = { confirmDeleteAll = false }) { Text("Cancel") } },
            title = { Text("Delete your account and all data?") },
            text = { Text("Removes your account, messages, devices, and memberships from this Skwod, then wipes what this device holds for it. This cannot be undone. (A Skwod owner must transfer or shut down instead.)") }
        )
    }

    confirmSignOut?.let { which ->
        val all = which == "all"
        val name = if (all) "all Skwods" else (model.current?.displayName ?: "this Skwod")
        AlertDialog(
            onDismissRequest = { confirmSignOut = null },
            confirmButton = {
                TextButton(onClick = {
                    confirmSignOut = null
                    scope.launch {
                        // The session token goes and nothing else: the cache, its key and the
                        // record of the skwod stay, so signing in again is the same device.
                        withContext(Dispatchers.IO) { if (all) model.signOut() else model.leaveCurrent() }
                        tick++; onSignOut()
                    }
                }) { Text("Sign out") }
            },
            dismissButton = { TextButton(onClick = { confirmSignOut = null }) { Text("Cancel") } },
            title = { Text("Sign out of $name?") },
            text = { Text("Your messages and keys stay on this device, locked. Sign in again with your password to carry on where you left off — no relinking.") }
        )
    }
    if (showErase) EraseDeviceDialog(onClose = { showErase = false }, onErased = { showErase = false; tick++; onSignOut() })

    if (showAdd) {
        Dialog(onDismissRequest = { showAdd = false }) {
            Surface(color = GlassDialogTone, shape = RoundedCornerShape(20.dp)) {
                AuthScreen(onDone = { showAdd = false })
            }
        }
    }
}

@Composable
fun PlayScreen() {
    var game by remember { mutableStateOf<String?>(null) }
    when (game) {
        "whiteboard" -> WhiteboardScreen()
        "chess" -> ChessScreen()
        else -> Column(Modifier.fillMaxSize().padding(24.dp)) {
            ScreenTitle("Play", subtitle = "Mini games & toys")
            Spacer(Modifier.height(16.dp))
            PlayCard("Whiteboard", "Sketch with friends", Icons.Filled.Brush) { game = "whiteboard" }
            PlayCard("Chess", "Pass-and-play 8×8", Icons.Filled.GridOn) { game = "chess" }
        }
    }
}

@Composable
private fun PlayCard(title: String, subtitle: String, icon: androidx.compose.ui.graphics.vector.ImageVector, onClick: () -> Unit) {
    Surface(color = GlassCardTone, shape = RoundedCornerShape(18.dp),
        modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp).clickable(onClick = onClick)) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = SkAccent)
            Spacer(Modifier.width(14.dp))
            Column {
                Text(title, color = Color.White)
                Text(subtitle, color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}
