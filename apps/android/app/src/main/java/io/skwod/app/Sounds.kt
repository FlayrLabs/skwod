package io.skwod.app

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.SoundPool

/**
 * The app's own short sounds (`res/raw/skwod_*.wav`, rendered by `tools/sounds/render.py` —
 * original, synthesised, nothing third-party). WHEN one is played is [AlertPolicy]'s decision;
 * this only plays it.
 *
 * Played as notification-usage audio: they follow the notification volume, mix with music
 * instead of taking audio focus from it, and are not played at all unless the ringer is in
 * its normal mode (silent and vibrate mean silent here too).
 */
object Sounds {
    const val SENT = 0
    const val RECEIVED = 1
    const val CALL_JOIN = 2
    const val CALL_LEAVE = 3

    private var pool: SoundPool? = null
    private val ids = IntArray(4)
    private val ready = BooleanArray(4)

    /** When the received sound was last played (ms; 0 = never) — the burst limit reads it. */
    @Volatile var lastReceivedAt: Long = 0
        private set

    @Synchronized private fun load(ctx: Context): SoundPool {
        pool?.let { return it }
        val attrs = AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_NOTIFICATION_EVENT)
            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
            .build()
        val p = SoundPool.Builder().setMaxStreams(2).setAudioAttributes(attrs).build()
        p.setOnLoadCompleteListener { _, sampleId, status ->
            val i = ids.indexOf(sampleId)
            if (i >= 0 && status == 0) ready[i] = true
        }
        val app = ctx.applicationContext
        ids[SENT] = p.load(app, R.raw.skwod_sent, 1)
        ids[RECEIVED] = p.load(app, R.raw.skwod_received, 1)
        ids[CALL_JOIN] = p.load(app, R.raw.skwod_call_join, 1)
        ids[CALL_LEAVE] = p.load(app, R.raw.skwod_call_leave, 1)
        pool = p
        return p
    }

    /** Load the samples ahead of the first use (the first play of an unloaded one is skipped). */
    fun warm(ctx: Context) { try { load(ctx) } catch (_: Exception) {} }

    fun play(ctx: Context, which: Int) {
        try {
            val audio = ctx.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
            if (audio != null && audio.ringerMode != AudioManager.RINGER_MODE_NORMAL) return
            val p = load(ctx)
            if (which == RECEIVED) lastReceivedAt = System.currentTimeMillis()
            if (ready[which]) p.play(ids[which], 1f, 1f, 1, 0, 1f)
        } catch (_: Exception) {
            // A sound that cannot be played is not worth a crash.
        }
    }
}
