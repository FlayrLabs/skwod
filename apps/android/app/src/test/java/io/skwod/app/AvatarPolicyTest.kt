package io.skwod.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Avatars ride ordinary channel messages, so who may set which one is decided here. The
 * security-review finding these pin down: `server:` / `skwod:` keys used to be accepted from the
 * pinned owner of WHICHEVER server carried the message, so the owner of server A could overwrite
 * server B's icon, or the skwod's.
 */
class AvatarPolicyTest {
    private val now = 1_800_000_000_000L

    /** Messages carried by a channel of server A; alice owns A, the host owns the instance. */
    private val inA = AvatarAuthority(serverId = "srv-a", serverOwner = "alice", instanceId = "inst-1", instanceOwner = "host")

    @Test fun aUserAvatarIsSetOnlyByThatUser() {
        assertTrue(AvatarPolicy.mayWrite("user:bob", "bob", "me", inA))
        assertFalse(AvatarPolicy.mayWrite("user:bob", "alice", "me", inA))          // not even the server owner
        assertFalse(AvatarPolicy.mayWrite("user:bob", "host", "me", inA))           // nor the instance owner
        // This device's own rows carry "__me__".
        assertTrue(AvatarPolicy.mayWrite("user:me", "__me__", "me", inA))
        assertFalse(AvatarPolicy.mayWrite("user:bob", "__me__", "me", inA))
        assertFalse(AvatarPolicy.mayWrite("user:me", "__me__", null, inA))
    }

    @Test fun aServerIconIsSetOnlyByTheOwnerOfTheServerThatCarriedIt() {
        assertTrue(AvatarPolicy.mayWrite("server:srv-a", "alice", "me", inA))
        assertFalse(AvatarPolicy.mayWrite("server:srv-a", "bob", "me", inA))
        // THE FINDING: alice owns A, and posts a pointer for server B in one of A's channels.
        assertFalse(AvatarPolicy.mayWrite("server:srv-b", "alice", "me", inA))
        // B's real owner cannot set B's icon through a channel of A either (wrong carrier).
        assertFalse(AvatarPolicy.mayWrite("server:srv-b", "bella", "me", inA))
        // ...but can from B's own channel.
        val inB = AvatarAuthority("srv-b", "bella", "inst-1", "host")
        assertTrue(AvatarPolicy.mayWrite("server:srv-b", "bella", "me", inB))
        assertFalse(AvatarPolicy.mayWrite("server:srv-b", "alice", "me", inB))
        // Prefix games.
        assertFalse(AvatarPolicy.mayWrite("server:srv-a-2", "alice", "me", inA))
        assertFalse(AvatarPolicy.mayWrite("server:", "alice", "me", inA))
        // I own A myself.
        assertTrue(AvatarPolicy.mayWrite("server:srv-a", "__me__", "alice", inA))
    }

    @Test fun aServerOwnerCannotSetTheSkwodIcon() {
        assertFalse(AvatarPolicy.mayWrite("skwod:inst-1", "alice", "me", inA))
        assertFalse(AvatarPolicy.mayWrite("skwod:inst-1", "bob", "me", inA))
    }

    @Test fun theInstanceOwnerSetsTheSkwodIconOnlyForThisInstance() {
        assertTrue(AvatarPolicy.mayWrite("skwod:inst-1", "host", "me", inA))
        assertFalse(AvatarPolicy.mayWrite("skwod:inst-2", "host", "me", inA))
        assertFalse(AvatarPolicy.mayWrite("skwod:", "host", "me", inA))
        // Being the instance owner does not make one the owner of a server.
        assertFalse(AvatarPolicy.mayWrite("server:srv-a", "host", "me", inA))
    }

    @Test fun unpinnedOwnersAndUnknownIdsAuthorizeNobody() {
        val nothingPinned = AvatarAuthority(serverId = "srv-a", serverOwner = null, instanceId = "inst-1", instanceOwner = null)
        assertFalse(AvatarPolicy.mayWrite("server:srv-a", "alice", "me", nothingPinned))
        assertFalse(AvatarPolicy.mayWrite("skwod:inst-1", "host", "me", nothingPinned))
        val noIds = AvatarAuthority(serverId = null, serverOwner = "alice", instanceId = null, instanceOwner = "host")
        assertFalse(AvatarPolicy.mayWrite("server:srv-a", "alice", "me", noIds))
        assertFalse(AvatarPolicy.mayWrite("skwod:inst-1", "host", "me", noIds))
        val empty = AvatarAuthority("", "", "", "")
        assertFalse(AvatarPolicy.mayWrite("server:", "", "me", empty))
        assertFalse(AvatarPolicy.mayWrite("skwod:", "", "me", empty))
        assertFalse(AvatarPolicy.mayWrite("server:", "__me__", "", empty))
        assertFalse(AvatarPolicy.mayWrite("server:srv-a", "alice", "me", AvatarAuthority()))
        // No author, or a key of no known kind.
        assertFalse(AvatarPolicy.mayWrite("user:bob", null, "me", inA))
        assertFalse(AvatarPolicy.mayWrite("user:bob", "", "me", inA))
        assertFalse(AvatarPolicy.mayWrite("channel:x", "alice", "me", inA))
        assertFalse(AvatarPolicy.mayWrite("", "alice", "me", inA))
    }

    @Test fun aPointerDatedInTheFutureIsRejected() {
        assertTrue(AvatarPolicy.plausible(now, now))
        assertTrue(AvatarPolicy.plausible(now - 86_400_000L, now))
        assertTrue(AvatarPolicy.plausible(now + 4 * 60 * 1000, now))           // clock skew
        assertFalse(AvatarPolicy.plausible(now + 6 * 60 * 1000, now))
        assertFalse(AvatarPolicy.plausible(Long.MAX_VALUE, now))               // would outrank every later update
        assertFalse(AvatarPolicy.plausible(0, now))
        assertFalse(AvatarPolicy.plausible(-1, now))
    }

    @Test fun onlySmallPicturesAreStored() {
        assertTrue(AvatarPolicy.acceptableSize(30_000))
        assertTrue(AvatarPolicy.acceptableSize(512 * 1024))
        assertFalse(AvatarPolicy.acceptableSize(512 * 1024 + 1))
        assertFalse(AvatarPolicy.acceptableSize(0))
        assertTrue(AvatarPolicy.acceptableDimensions(256, 256))
        assertTrue(AvatarPolicy.acceptableDimensions(2048, 2048))
        assertFalse(AvatarPolicy.acceptableDimensions(2049, 16))
        assertFalse(AvatarPolicy.acceptableDimensions(60_000, 60_000))
        assertFalse(AvatarPolicy.acceptableDimensions(0, 10))
        assertFalse(AvatarPolicy.acceptableDimensions(-1, -1))
    }
}
