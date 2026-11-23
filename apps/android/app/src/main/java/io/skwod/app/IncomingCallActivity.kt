package io.skwod.app

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CallEnd
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.*
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * The ONLY screen of this app that may appear over the lock screen, and it shows exactly three
 * things: who is calling, Answer, Decline. No chat, no names of other people, no navigation.
 *
 * - Not exported: it can only be started by this app's own notification PendingIntents, and even
 *   then it acts only if the intent carries this process's nonce and names the call that is
 *   ringing right now ([IntentGuard]). Anything else finishes immediately.
 * - **Answering unlocks first.** Answer asks the system to dismiss the keyguard; with a PIN /
 *   pattern / biometric set, the user must authenticate before any app content — including the
 *   call screen — is shown. Only then is the call handed to [MainActivity], which never shows
 *   over the lock screen.
 * - The show-when-locked flag exists only while this ring is live and this activity is started:
 *   it is cleared in onStop, on answer, on decline and when the ring ends.
 */
class IncomingCallActivity : ComponentActivity() {
    private var serverId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val model = AppModel.get(this)
        if (!accept(intent)) { finish(); return }
        val answerNow = intent.action == Notifications.ACTION_ANSWER
        setContent {
            SkwodTheme {
                val ring = model.incomingCall
                // The ring ended (timed out, declined elsewhere, answered): nothing left to show.
                LaunchedEffect(ring) { if (ring == null || ring.serverId != serverId) close() }
                LaunchedEffect(Unit) { if (answerNow) answer() }
                Box(Modifier.fillMaxSize().background(Color(0xFF0A0A12)), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(32.dp)) {
                        Text("Incoming Skwod call", color = Color.White.copy(alpha = 0.6f), fontSize = 14.sp)
                        Spacer(Modifier.height(10.dp))
                        Text(ring?.callerName ?: "", color = Color.White, fontSize = 28.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(8.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Lock, null, tint = Color(0xFF4ADE80), modifier = Modifier.size(14.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("End-to-end encrypted", color = Color(0xFF4ADE80), fontSize = 13.sp)
                        }
                        Spacer(Modifier.height(48.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(48.dp)) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                IconButton(onClick = { decline() }, modifier = Modifier.size(72.dp).background(Color(0xFFEF4444), CircleShape)) {
                                    Icon(Icons.Filled.CallEnd, "Decline", tint = Color.White)
                                }
                                Spacer(Modifier.height(6.dp)); Text("Decline", color = Color.White.copy(alpha = 0.7f), fontSize = 13.sp)
                            }
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                IconButton(onClick = { answer() }, modifier = Modifier.size(72.dp).background(Color(0xFF22C55E), CircleShape)) {
                                    Icon(Icons.Filled.Call, "Answer", tint = Color.White)
                                }
                                Spacer(Modifier.height(6.dp)); Text("Answer", color = Color.White.copy(alpha = 0.7f), fontSize = 13.sp)
                            }
                        }
                        Spacer(Modifier.height(24.dp))
                        Text("Unlock to answer.", color = Color.White.copy(alpha = 0.45f), fontSize = 12.sp)
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (!accept(intent)) { close(); return }
        if (intent.action == Notifications.ACTION_ANSWER) answer()
    }

    /** Our own PendingIntent (nonce) for the call that is ringing right now — or nothing. */
    private fun accept(intent: Intent?): Boolean {
        val id = intent?.getStringExtra(Notifications.EXTRA_SERVER_ID)
        val ok = IntentGuard.isForRingingCall(intent?.getStringExtra(IntentGuard.EXTRA_NONCE), id,
            AppModel.get(this).incomingCall?.serverId)
        if (ok) serverId = id
        return ok
    }

    override fun onStart() {
        super.onStart()
        // Over the lock screen only while this exact ring is live.
        val live = serverId != null && AppModel.get(this).incomingCall?.serverId == serverId
        setOverLockScreen(live)
        if (!live) close()
    }

    override fun onStop() {
        setOverLockScreen(false)
        super.onStop()
    }

    private fun setOverLockScreen(on: Boolean) {
        if (android.os.Build.VERSION.SDK_INT >= 27) { setShowWhenLocked(on); setTurnScreenOn(on) }
    }

    private fun decline() {
        Notifications.cancelIncomingCall(this)
        AppModel.get(this).incomingCall = null
        close()
    }

    /** Unlock FIRST; only a dismissed keyguard lets the call (or anything else) appear. */
    private fun answer() {
        val id = serverId ?: return close()
        val km = getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        if (km == null || !km.isKeyguardLocked) { proceed(id); return }
        km.requestDismissKeyguard(this, object : KeyguardManager.KeyguardDismissCallback() {
            override fun onDismissSucceeded() { proceed(id) }
            // Cancelled or failed authentication: keep ringing, show nothing more.
        })
    }

    private fun proceed(id: String) {
        val model = AppModel.get(this)
        val call = model.incomingCall
        if (call == null || call.serverId != id) { close(); return }    // the ring ended meanwhile
        // Switches to the ringing skwod first if it is not the one on screen, then opens the call.
        model.answerIncoming(call)
        setOverLockScreen(false)
        startActivity(Intent(this, MainActivity::class.java).setAction(Intent.ACTION_MAIN)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP))
        finish()
    }

    private fun close() {
        setOverLockScreen(false)
        if (!isFinishing) finish()
    }
}
