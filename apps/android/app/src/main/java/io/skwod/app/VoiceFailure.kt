package io.skwod.app

/**
 * Why joining a call failed, stage by stage, and the one fixed sentence for it (build 51). Same
 * rule and words as the Apple app's `VoiceFailure.swift` (`shared-test-vectors/voice-failures.json`).
 * Nothing a host or the media engine said is ever shown: their errors can carry an address.
 */
enum class VoiceFailure(val code: String, val message: String) {
    OFF("off", "Voice is off on this Skwod right now. Ask the host to check it."),
    STARTING("starting", "Voice is starting on this Skwod. Try again in a moment."),
    UNREACHABLE("unreachable", "Couldn't reach the host. Check your connection and try again."),
    NO_ACCESS("no_access", "You can't join this channel. Ask the host to let you in."),
    UNAVAILABLE("unavailable", "The host didn't open the call. Try again in a moment."),
    PORT_TAKEN("port_taken", "Another call is using this device's sound and video path. End it, then try again."),
    MEDIA_BLOCKED("media_blocked", "Reached the call, but this device's connection blocked its sound and video. Joining on Wi-Fi may work."),
    MEDIA_SILENT("media_silent", "Reached the call, but sound and video didn't get through. Try again in a moment."),
    OTHER("other", "Couldn't join the call. Try again.");

    /** Tried once more by itself: nothing was joined yet, and waiting may be all it takes. */
    val retriesOnce: Boolean get() = this == STARTING || this == UNREACHABLE

    /** The voice tunnel's counters (`SkwodClient.voiceTunnel`). */
    data class Counters(val accepted: Long, val up: Long, val down: Long, val undelivered: Long)

    companion object {
        /**
         * The core's `CoreException.Voice` code. What happened to the media is never a code: that
         * is worked out here, from the tunnel's counters.
         */
        fun of(code: String): VoiceFailure =
            entries.firstOrNull { it.code == code && it != MEDIA_BLOCKED && it != MEDIA_SILENT } ?: OTHER

        /**
         * The media engine gave up: where? This device's own network is only ever suspected when
         * the call server accepted the signaling socket during THIS attempt, and either nothing the
         * engine sent reached the tunnel or none of the host's answers could be handed back to it.
         */
        fun media(before: Counters?, after: Counters?): VoiceFailure {
            if (before == null || after == null) return OTHER
            if (after.accepted < before.accepted || after.up < before.up || after.down < before.down || after.undelivered < before.undelivered) return OTHER
            if (after.accepted == before.accepted) return UNREACHABLE
            val down = after.down - before.down
            if (after.up == before.up) return MEDIA_BLOCKED
            if (down > 0 && after.undelivered - before.undelivered >= down) return MEDIA_BLOCKED
            return MEDIA_SILENT
        }
    }
}

/** What the Voice row does, from the host's live status (`SkwodClient.voiceConfig`). */
sealed interface VoiceGate {
    data object Join : VoiceGate

    /**
     * The owner's panel for a call server of their own. Never where the skwod has one built in:
     * saving another there kept the built-in one off on every start.
     */
    data object SetUp : VoiceGate
    data class Say(val text: String) : VoiceGate

    companion object {
        const val NOT_SET_UP = "Voice isn't set up yet — ask the host to turn it on."

        fun decide(configured: Boolean, status: String, bundled: Boolean, owner: Boolean): VoiceGate = when {
            configured -> Join
            status == "starting" -> Say(VoiceFailure.STARTING.message)
            bundled -> Say(VoiceFailure.OFF.message)
            owner -> SetUp
            else -> Say(NOT_SET_UP)
        }
    }
}
