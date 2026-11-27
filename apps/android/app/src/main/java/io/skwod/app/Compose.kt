package io.skwod.app

/**
 * Build 51: what a person sends goes where they sent it (the twin of Compose.swift). Everything
 * about a send is settled at the tap — which skwod's cache, which conversation, whom, what — and
 * nothing is read again after it, so a conversation or a skwod opened a moment later changes nothing.
 */
object Compose {
    const val OPENING = "Opening… Your message is still here — send it again in a moment."

    /**
     * What a send from a conversation of skwod [home] goes through: that skwod's client, its cache
     * open right now — or null (nothing is taken from the composer, and it says so). Never whichever
     * client happens to be there.
     */
    fun <C> sender(bound: BoundClient<C>?, home: String?): BoundClient<C>? =
        bound?.takeIf { it.cacheOpen && !home.isNullOrEmpty() && it.workspaceId == home }

    /** Text that could not be queued comes back to its own composer, before whatever was typed since. */
    fun givenBack(text: String, draft: String): String = if (draft.isEmpty()) text else "$text\n$draft"

    /** A direct conversation's key: its screen's identity, and what its draft is kept under. */
    fun directKey(workspaceId: String?, conversationId: String) = "${workspaceId ?: ""}|dm|$conversationId"
}
