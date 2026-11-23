package io.skwod.app

/**
 * What both devices say while one pairs by QR (build 48). Anyone can print a QR, so a scanned
 * one is never a reason to type a password (pairing needs none), and nothing claims the code came
 * from "your other device": the new device names the host by its key (or by a name this device
 * already knows it by) and asks before it dials, and the person picks the matching emoji on the
 * device they already use. Same words as the Apple app's `PairingCopy`.
 */
object PairingCopy {
    fun header(shortKey: String, username: String, known: Boolean): String =
        "${if (known) "A Skwod you use" else "A new Skwod"} · $shortKey · @$username"

    /**
     * Asked before the new device dials anything. [knownName] comes only from a workspace this
     * device already has for that host — never from the QR or the host itself.
     */
    fun joinPrompt(knownName: String?, shortKey: String, username: String): String =
        "Join ${knownName?.trim()?.takeIf { it.isNotEmpty() } ?: shortKey} as @$username?"

    const val JOIN_DETAIL = "Continue only if you just scanned this on a device of yours. Anyone can print a QR code, and one from someone else would add this device to their account instead."

    const val WAITING_FOR_OTHER = "Waiting for your other device to see this one…"

    const val CONFIRM = "On the device you already use, pick the set that matches these five. If none of them match, choose “None of these” there."

    /** Shown once approved, before this device enters the account. */
    fun approved(shortKey: String): String = "Approved on your other device · $shortKey"

    const val NOT_APPROVED = "This device wasn't added: it was denied on your other device, or the code expired. Make a new code there to try again."

    const val MISMATCH = "This device wasn't added: the code didn't check out, so someone may have tampered with it. Make a new code on your other device."

    /** What to show when pairing stops with [detail]: each refusal reads as what it is. */
    fun failure(detail: String): String {
        val d = detail.lowercase()
        return when {
            d.contains("did not match") -> MISMATCH
            d.contains("not approved") || d.contains("expired") -> NOT_APPROVED
            d.startsWith("protocol error:") -> detail.substring("protocol error:".length).trim().replaceFirstChar { it.uppercase() }
            else -> detail
        }
    }

    // The device that shows the QR.
    const val PICK_TITLE = "Which set does the new device show?"
    const val PICK_HINT = "Pick the five emoji on the device in your hand. Picking a set it doesn't show refuses it. It will be able to read your new messages."
    const val NONE_OF_THESE = "None of these"
}
