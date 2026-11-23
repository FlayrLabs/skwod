package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Invites are untrusted input (deep links, QR codes, pasted text): only two shapes are accepted. */
class InviteLinkTest {
    private val node = "ybndrfg8ejkmcpqxot1uwisza345h769ybndrfg8ejkmcpqxot1u"   // 52 z-base-32 chars

    private fun reason(raw: String): InviteException.Reason? =
        try { InviteLink.parse(raw); null } catch (e: InviteException) { e.reason }

    @Test fun p2pInviteWithCode() {
        val inv = InviteLink.parse("skwod://join/$node#SKWD-AB12-CD34")
        assertEquals(SkwodAddress.P2p(node, null), inv.address)
        assertEquals("SKWD-AB12-CD34", inv.joinCode)
        assertEquals("skwod://join/$node", inv.address.stored)
    }

    @Test fun p2pAddressOnlyAndSurroundingWhitespace() {
        val inv = InviteLink.parse("  skwod://join/$node\n")
        assertNull(inv.joinCode)
        assertEquals(node, (inv.address as SkwodAddress.P2p).nodeId)
    }

    @Test fun p2pFallbackMustBeHttps() {
        val ok = InviteLink.parse("skwod://join/$node?x=1&u=https://chat.example.org&l=abcd#tok_1")
        assertEquals("https://chat.example.org", (ok.address as SkwodAddress.P2p).fallbackUrl)
        assertEquals("tok_1", ok.joinCode)
        val bad = InviteLink.parse("skwod://join/$node?u=http://evil.example#abc")
        assertNull((bad.address as SkwodAddress.P2p).fallbackUrl)
    }

    @Test fun rejectsMalformedP2p() {
        assertEquals(InviteException.Reason.NotAnInvite, reason("skwod://join/notakey#code"))
        assertEquals(InviteException.Reason.NotAnInvite, reason("skwod://join/${node}x#code"))
        assertEquals(InviteException.Reason.NotAnInvite, reason("skwod://evil/$node#code"))
        assertEquals(InviteException.Reason.NotAnInvite, reason("skwod:join/$node"))
        assertEquals(InviteException.Reason.BadCode, reason("skwod://join/$node#bad!code"))
        assertEquals(InviteException.Reason.NotAnInvite, reason("skwod://join/$node#a b"))
        assertEquals(InviteException.Reason.NotAnInvite, reason("skwod://join/$node#a\u0000b"))
    }

    @Test fun rejectsEmptyAndOversized() {
        assertEquals(InviteException.Reason.Empty, reason("   "))
        assertEquals(InviteException.Reason.TooLong, reason("skwod://join/$node#" + "a".repeat(2000)))
    }

    @Test fun classicHttpsInvite() {
        val inv = InviteLink.parse("chat.example.org#SKWD-AAAA-BBBB~b.abcd.ef01")
        assertEquals(SkwodAddress.Https("https://chat.example.org"), inv.address)
        assertEquals("SKWD-AAAA-BBBB", inv.joinCode)
        assertEquals("https://chat.example.org", InviteLink.parse("https://chat.example.org/").address.stored)
    }

    @Test fun cleartextOnlyForLoopback() {
        assertEquals(InviteException.Reason.InsecureAddress, reason("http://chat.example.org#abc"))
        assertEquals(InviteException.Reason.InsecureAddress, reason("http://10.0.2.2:3000"))
        assertEquals(InviteException.Reason.InsecureAddress, reason("http://localhost:3000"))
        assertEquals("http://127.0.0.1:38411", InviteLink.parse("http://127.0.0.1:38411").address.stored)
    }

    @Test fun rejectsOtherSchemesAndCredentials() {
        assertEquals(InviteException.Reason.NotAnInvite, reason("javascript://alert(1)"))
        assertEquals(InviteException.Reason.NotAnInvite, reason("file:///etc/passwd"))
        assertEquals(InviteException.Reason.NotAnInvite, reason("https://user:pw@chat.example.org"))
        assertEquals(InviteException.Reason.NotAnInvite, reason("https://chat.example.org?x=1"))
    }

    @Test fun formatRoundTrips() {
        val link = InviteLink.format(node, "SKWD-AB12-CD34", "https://chat.example.org")
        assertEquals("skwod://join/$node?u=https://chat.example.org#SKWD-AB12-CD34", link)
        assertEquals("SKWD-AB12-CD34", InviteLink.parse(link!!).joinCode)
        assertNull(InviteLink.format("short", "abc"))
    }

    @Test fun shareLinkRoundTripsAndEqualsTheAppForm() {
        val share = InviteLink.shareLink(node, "SKWD-AB12-CD34")
        assertEquals("https://skwod.io/join#$node.SKWD-AB12-CD34", share)
        assertEquals(InviteLink.parse("skwod://join/$node#SKWD-AB12-CD34"), InviteLink.parse(share!!))
        assertEquals("skwod://join/$node", InviteLink.parse(share).address.stored)
        assertEquals("https://skwod.io/join#$node", InviteLink.shareLink(node, null))
        assertNull(InviteLink.parse("https://skwod.io/join#$node").joinCode)
        assertNull(InviteLink.parse("https://skwod.io/join#$node.").joinCode)
        val withFallback = InviteLink.shareLink(node, "abc", "https://chat.example.org")
        assertEquals("https://skwod.io/join#$node.abc&u=https://chat.example.org", withFallback)
        assertEquals(InviteLink.parse("skwod://join/$node?u=https://chat.example.org#abc"), InviteLink.parse(withFallback!!))
        assertNull((InviteLink.parse("https://skwod.io/join#$node.abc&x=1&u=http://evil.example&l=zz").address as SkwodAddress.P2p).fallbackUrl)
        assertNull(InviteLink.shareLink("short", "abc"))
        assertNull(InviteLink.shareLink(node, "bad code"))
    }

    @Test fun shareLinkAcceptsOnlyTheExactOriginAndPath() {
        for (ok in listOf("https://skwod.io/join#$node.abc", "https://skwod.io/join/#$node.abc",
            "HTTPS://Skwod.IO/join#$node.abc", "  https://skwod.io/join#$node.abc\n")) {
            assertEquals(ok, "abc", InviteLink.parse(ok).joinCode)
        }
        for (bad in listOf("https://skwod.io", "https://skwod.io/", "https://skwod.io/join", "https://skwod.io/join#",
            "https://skwod.io/joined#$node.abc", "https://skwod.io/join/x#$node.abc", "https://skwod.io/#$node.abc",
            "https://skwod.io:8443/join#$node.abc", "https://skwod.io/join?n=$node#$node.abc",
            "https://skwod.io/join?u=https://chat.example.org#$node.abc", "https://skwod.io/join#notakey.abc",
            "https://skwod.io/join#${node}x.abc")) {
            assertEquals(bad, InviteException.Reason.NotAnInvite, reason(bad))
        }
        assertEquals(InviteException.Reason.BadCode, reason("https://skwod.io/join#$node.a.b"))
        assertEquals(InviteException.Reason.BadCode, reason("https://skwod.io/join#$node.bad!code"))
        // Look-alike hosts are not the share origin: they fall through to the plain-address rules
        // and are never read as a p2p invite.
        assertFalse(InviteLink.isOnShareOrigin("https://skwod.io.evil.example/join#$node.abc"))
        assertFalse(InviteLink.isOnShareOrigin("https://chat.skwod.io/join#$node.abc"))
        assertFalse(InviteLink.isOnShareOrigin("http://skwod.io/join#$node.abc"))
        assertEquals(InviteException.Reason.BadCode, reason("https://skwod.io.evil.example/join#$node.abc"))
        assertEquals(InviteException.Reason.InsecureAddress, reason("http://skwod.io/join#$node.abc"))
    }

    @Test fun codeCharset() {
        assertTrue(InviteLink.isValidCode("SKWD-AB12-CD34"))
        assertTrue(InviteLink.isValidCode("tok_en-123"))
        assertFalse(InviteLink.isValidCode(""))
        assertFalse(InviteLink.isValidCode("a/b"))
        assertFalse(InviteLink.isValidCode("a".repeat(129)))
    }

    /** Keys are provisioned only to the exact account that was approved (username lookups can lie). */
    @Test fun provisioningRequiresTheSameAccount() {
        assertTrue(isSameAccount("u1", "u1"))
        assertFalse(isSameAccount("u2", "u1"))
        assertFalse(isSameAccount(null, "u1"))
        assertFalse(isSameAccount("", ""))
    }

    @Test fun deviceLinkCodeFromQr() {
        assertEquals("ABCD-EFGH-JKLM-NPQR", Qr.linkCode("skwod-link:ABCD-EFGH-JKLM-NPQR"))
        assertEquals("ABCD-EFGH-JKLM-NPQR", Qr.linkCode(" ABCD-EFGH-JKLM-NPQR "))
        assertNull(Qr.linkCode("skwod-link:short"))
        assertNull(Qr.linkCode("skwod://join/$node"))
        assertNull(Qr.linkCode("skwod-link:ABCD EFGH JKLM NPQR; rm -rf"))
    }

    /** The scanner path, without a camera: a QR's luminance plane decodes offline with ZXing. */
    @Test fun qrDecodesFromALuminancePlane() {
        val text = "skwod://join/$node#SKWD-AB12-CD34"
        val size = 320
        val matrix = com.google.zxing.qrcode.QRCodeWriter().encode(text, com.google.zxing.BarcodeFormat.QR_CODE, size, size)
        val y = ByteArray(size * size) { i -> if (matrix.get(i % size, i / size)) 0x10.toByte() else 0xF0.toByte() }
        assertEquals(text, Qr.decode(y, size, size))
        assertEquals("SKWD-AB12-CD34", InviteLink.parse(Qr.decode(y, size, size)!!).joinCode)
        assertNull(Qr.decode(ByteArray(size * size) { 0x7F }, size, size))      // no code in the frame
    }

    @Test fun relayHintIsKeptOnlyForAllowListedRelays() {
        // Its own node id: parsing an `&r=` link records a hint, and other tests compare exact links.
        val rnode = node.reversed()
        val ok = InviteLink.parse("https://skwod.io/join#$rnode.abc&r=https://use1-1.relay.n0.iroh.link./")
        assertEquals("https://use1-1.relay.n0.iroh.link/", ok.relayHint)
        assertEquals("https://use1-1.relay.n0.iroh.link/", RelayHints.get(rnode))
        assertEquals("https://use1-1.relay.n0.iroh.link/", InviteLink.parse("skwod://join/$rnode?r=https://use1-1.relay.n0.iroh.link/#abc").relayHint)
        for (bad in listOf(
            "http://use1-1.relay.n0.iroh.link/", "https://relay.n0.iroh.link/", "https://evil.example/",
            "https://use1-1.relay.n0.iroh.link.evil.example/", "https://use1-1.relay.n0.iroh.link:8443/",
            "https://use1-1.relay.n0.iroh.link/x", "https://-x.relay.n0.iroh.link/",
        )) {
            assertNull(bad, InviteLink.allowedRelay(bad))
            assertNull(bad, InviteLink.parse("https://skwod.io/join#$rnode&r=$bad").relayHint)
        }
        val link = InviteLink.shareLink(rnode, "abc", relayUrl = "https://use1-1.relay.n0.iroh.link/")
        assertEquals("https://skwod.io/join#$rnode.abc&r=https://use1-1.relay.n0.iroh.link/", link)
    }
}
