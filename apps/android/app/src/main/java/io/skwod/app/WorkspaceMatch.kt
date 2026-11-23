package io.skwod.app

/**
 * Deciding whether a skwod we just authenticated against is one we ALREADY hold a workspace for.
 *
 * This decision hands the new connection the old workspace's encrypted cache — device identity
 * keys, space keys, decrypted history — so it must rest on something the other side cannot fake:
 *
 * - **p2p**: the node id, and nothing else. The QUIC handshake fails unless the host holds that
 *   key, so "same node id" is a cryptographic fact. What the host *says* about itself (its
 *   `instanceId`, its signing key) is never used to find a workspace: a malicious host can claim
 *   any instance id it likes. A p2p address never matches a classic workspace, or the reverse.
 * - **classic https**: a workspace is reused only if the server proves — by signing a fresh
 *   challenge — that it holds the key that workspace pinned ([verifyPinned]). A claimed instance
 *   id or a matching URL only nominates a candidate. The one exception is a workspace from before
 *   key pinning existed (no pinned key to check): it is reused for the exact same https URL only,
 *   which TLS authenticates.
 *
 * In every case the account must be the same one; another account on the same skwod is a
 * separate workspace with its own keys.
 */
object WorkspaceMatch {
    /**
     * @param claimedInstanceId what the server reports about itself — untrusted, a hint only
     * @param verifyPinned proves the server at this address holds the given pinned key
     */
    suspend fun find(
        workspaces: List<Workspace>,
        address: SkwodAddress,
        userId: String,
        claimedInstanceId: String?,
        verifyPinned: suspend (pinnedKey: String) -> Boolean,
    ): Workspace? {
        when (address) {
            is SkwodAddress.P2p ->
                return workspaces.firstOrNull { it.nodeId == address.nodeId && it.userId == userId }
            is SkwodAddress.Https -> {
                val candidates = workspaces.filter { w ->
                    !w.isP2P && w.userId == userId &&
                        (w.server == address.url || (claimedInstanceId != null && w.instanceId == claimedInstanceId))
                }
                for (w in candidates) {
                    val pinned = w.pinnedKey
                    if (pinned == null) {
                        if (w.server == address.url) return w       // pre-pinning install, same TLS origin
                        continue
                    }
                    val proven = try { verifyPinned(pinned) } catch (_: Exception) { false }
                    if (proven) return w
                }
                return null
            }
        }
    }

    /**
     * The cache/keys id for a workspace that matched nothing. Derived from the address we dialed
     * and the account — never from anything the server claims — and guaranteed not to collide
     * with (and so never to replace or open) another workspace's data.
     */
    fun newLocalId(workspaces: List<Workspace>, address: SkwodAddress, userId: String): String {
        val base = Workspace.slug(address.stored)
        if (workspaces.none { it.localId == base }) return base
        var id = Workspace.slug(address.stored + "|" + userId)
        var n = 1
        while (workspaces.any { it.localId == id }) id = Workspace.slug(address.stored + "|" + userId + "|" + n++)
        return id
    }
}

/**
 * Which notification intents MainActivity / IncomingCallActivity act on. An intent's action and
 * extras prove nothing about who sent it, so the app's own PendingIntents carry a random nonce
 * that only exists in this process's memory, and call intents must also name the call that is
 * actually ringing.
 */
object IntentGuard {
    /** 128 random bits, new every process start. Never persisted, never logged. */
    val nonce: String by lazy {
        val b = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
        b.joinToString("") { "%02x".format(it) }
    }
    const val EXTRA_NONCE = "skwod_nonce"

    fun isOurs(presented: String?, expected: String = nonce): Boolean {
        if (presented == null || presented.length != expected.length) return false
        return java.security.MessageDigest.isEqual(presented.toByteArray(), expected.toByteArray())
    }

    /** A call intent is honoured only with our nonce AND for the call that is ringing right now. */
    fun isForRingingCall(presentedNonce: String?, serverId: String?, ringingServerId: String?, expected: String = nonce): Boolean =
        isOurs(presentedNonce, expected) && !serverId.isNullOrEmpty() && serverId == ringingServerId
}
