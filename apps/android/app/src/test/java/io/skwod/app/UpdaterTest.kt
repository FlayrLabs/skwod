package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64

/**
 * The updater trusts nothing it downloads: requests go only to GitHub's release hosts over https
 * (every redirect hop re-checked), and an apk installs only with the publisher's signature.
 */
class UpdaterTest {
    private val repo = "https://github.com/FlayrLabs/skwod-releases/releases"
    private val asset = "https://release-assets.githubusercontent.com/github-production-release-asset/1/abc?sp=r&sig=x"

    // ---- redirect allowlist ----

    @Test fun manifestUrlIsTheFixedGithubFeed() {
        assertEquals("$repo/latest/download/manifest.json", Updater.MANIFEST_URL)
        assertTrue(Updater.allowedStart(Updater.MANIFEST_URL))
    }

    @Test fun onlyGithubReleaseHostsOverHttps() {
        assertEquals(setOf("github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"),
            Updater.REDIRECT_HOSTS)
        assertTrue(Updater.allowedHost("https://github.com/x"))
        assertTrue(Updater.allowedHost("https://objects.githubusercontent.com/x?y=1"))
        assertTrue(Updater.allowedHost(asset))
        assertTrue(Updater.allowedHost("HTTPS://GitHub.com:443/x"))
        for (bad in listOf(
            "http://github.com/x",                                  // cleartext
            "https://github.com:8443/x",                            // other port
            "https://user@github.com/x",                            // credentials
            "https://github.com@evil.example/x",                    // host is evil.example
            "https://github.com.evil.example/x",                    // suffix trick
            "https://evilgithub.com/x",
            "https://raw.githubusercontent.com/x",                  // a GitHub host, but not a release host
            "https://sub.release-assets.githubusercontent.com/x",
            "https://github.com./x",
            "https://127.0.0.1/x", "https://[::1]/x",
            "ftp://github.com/x", "file:///etc/hosts", "skwod://join/abc", "//github.com/x", "", "https://",
        )) assertFalse(bad, Updater.allowedHost(bad))
    }

    @Test fun requestsStartOnlyInsideTheReleaseRepo() {
        assertTrue(Updater.allowedStart("$repo/download/v41/skwod-41.apk"))
        for (bad in listOf(
            asset,                                                                  // an asset host is a redirect target, never a start
            "https://github.com/someone-else/skwod-releases/releases/download/v41/skwod-41.apk",
            "https://github.com/FlayrLabs/other/releases/download/v41/skwod-41.apk",
            "$repo/download/v41/../../../../evil/x.apk",
            "$repo/download/v41/%2e%2e/x.apk",
            "$repo/download/v41/skwod-41.apk?x=1",
            "$repo/download/v41/skwod-41.apk#frag",
            "http://github.com/FlayrLabs/skwod-releases/releases/download/v41/skwod-41.apk",
            "$repo/",
        )) assertFalse(bad, Updater.allowedStart(bad))
    }

    @Test fun everyRedirectHopIsRevalidated() {
        assertEquals("$repo/download/v41/manifest.json", Updater.nextHop(Updater.MANIFEST_URL, "$repo/download/v41/manifest.json"))
        // Relative redirects resolve against the current URL and are then checked like any other.
        assertEquals("https://github.com/a/b", Updater.nextHop(Updater.MANIFEST_URL, "/a/b"))
        assertEquals(asset, Updater.nextHop("$repo/download/v41/manifest.json", asset))
        assertNull(Updater.nextHop(Updater.MANIFEST_URL, "http://github.com/a"))              // downgrade
        assertNull(Updater.nextHop(Updater.MANIFEST_URL, "//evil.example/a"))                 // scheme-relative
        assertNull(Updater.nextHop(Updater.MANIFEST_URL, "https://evil.example/a"))
        assertNull(Updater.nextHop(asset, "https://github.com.evil.example/a"))
        assertNull(Updater.nextHop(Updater.MANIFEST_URL, null))
        assertNull(Updater.nextHop(Updater.MANIFEST_URL, " "))
        assertNull(Updater.nextHop(Updater.MANIFEST_URL, "https://exa mple/"))
    }

    /** A fake network: url -> response. Records every URL that was actually requested. */
    private fun walk(start: String, net: Map<String, Updater.Hop>): Pair<String?, List<String>> {
        val asked = mutableListOf<String>()
        val end = Updater.resolve(start) { url -> asked += url; net[url] ?: Updater.Hop(404, null) }
        return end to asked
    }

    @Test fun followsGithubsRealChain() {
        val tagged = "$repo/download/v41/manifest.json"
        val (end, asked) = walk(Updater.MANIFEST_URL, mapOf(
            Updater.MANIFEST_URL to Updater.Hop(302, tagged),
            tagged to Updater.Hop(302, asset),
            asset to Updater.Hop(200, null)))
        assertEquals(asset, end)
        assertEquals(listOf(Updater.MANIFEST_URL, tagged, asset), asked)
    }

    @Test fun neverContactsAHostOutsideTheAllowlist() {
        val evil = "https://evil.example/manifest.json"
        // Hop 2 leaves the allowlist: the chain stops and evil.example is never asked.
        val tagged = "$repo/download/v41/manifest.json"
        val (end, asked) = walk(Updater.MANIFEST_URL, mapOf(
            Updater.MANIFEST_URL to Updater.Hop(302, tagged),
            tagged to Updater.Hop(302, evil),
            evil to Updater.Hop(200, null)))
        assertNull(end)
        assertEquals(listOf(Updater.MANIFEST_URL, tagged), asked)

        // A start URL outside the repo is refused before any request.
        val (end2, asked2) = walk(evil, mapOf(evil to Updater.Hop(200, null)))
        assertNull(end2); assertTrue(asked2.isEmpty())

        // http downgrade mid-chain.
        val (end3, asked3) = walk(Updater.MANIFEST_URL, mapOf(
            Updater.MANIFEST_URL to Updater.Hop(301, "http://github.com/FlayrLabs/skwod-releases/x")))
        assertNull(end3); assertEquals(1, asked3.size)
    }

    @Test fun stopsOnLoopsAndErrors() {
        val (end, asked) = walk(Updater.MANIFEST_URL, mapOf(Updater.MANIFEST_URL to Updater.Hop(302, Updater.MANIFEST_URL)))
        assertNull(end); assertEquals(6, asked.size)                       // 1 request + 5 redirects, then give up
        assertNull(walk(Updater.MANIFEST_URL, emptyMap()).first)           // 404
        assertNull(walk(Updater.MANIFEST_URL, mapOf(Updater.MANIFEST_URL to Updater.Hop(302, null))).first)
        assertNull(walk(Updater.MANIFEST_URL, mapOf(Updater.MANIFEST_URL to Updater.Hop(500, asset))).first)
    }

    // ---- manifest + publisher signature ----

    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    /** A throwaway publisher: (public key base64, sign(message) -> base64). */
    private fun publisher(): Pair<String, (ByteArray) -> String> {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val raw = kp.public.encoded.takeLast(32).toByteArray()             // bare 32-byte key, as pinned
        return Base64.getEncoder().encodeToString(raw) to { digest ->
            val s = Signature.getInstance("Ed25519"); s.initSign(kp.private); s.update(digest)
            Base64.getEncoder().encodeToString(s.sign())
        }
    }

    private fun tempApk(bytes: ByteArray): File = File.createTempFile("skwod-test", ".apk").apply { writeBytes(bytes); deleteOnExit() }

    /** A manifest the way sign-manifest.sh writes it: unsigned legacy fields + the signed statement. */
    private fun manifest(sign: (ByteArray) -> String, statement: String, legacy: String = statement): String {
        val raw = statement.toByteArray()
        val sig = sign(Updater.STATEMENT_LABEL.toByteArray() + raw)
        val legacyAndroid = org.json.JSONObject(legacy).optJSONObject("android")
        return org.json.JSONObject().put("android", legacyAndroid)
            .put("signed", Base64.getEncoder().encodeToString(raw)).put("signed_sig", sig).toString()
    }
    private val now = 1_800_000_000L
    private fun statement(build: Int = 41, notes: String = "hi", issued: Long = now, expires: Long = now + 120 * 86400L) =
        """{"v":1,"issued":$issued,"expires":$expires,"android":{"build":$build,"version":"0.1.0","file":"skwod-$build.apk",
            "url":"$repo/download/v$build/skwod-$build.apk","sha256":"ab","sig2":"cd","notes":"$notes"},
            "ios":{"build":$build,"version":"0.1.0","testflight":"https://testflight.apple.com/join/x"}}"""

    @Test fun manifestOffersOnlyANewerBuild() {
        val (pub, sign) = publisher()
        val body = manifest(sign, statement())
        val a = Updater.parseManifest(body, 40, pub, now)!!
        assertEquals(41, a.build); assertEquals("0.1.0", a.version); assertEquals("hi", a.notes)
        assertEquals("$repo/download/v41/skwod-41.apk", a.url)
        assertEquals("ab", a.sha256); assertEquals("cd", a.sig)
        assertNull(Updater.parseManifest(body, 41, pub, now))               // same build: nothing to offer
        assertNull(Updater.parseManifest(body, 99, pub, now))
        assertNull(Updater.parseManifest("{}", 40, pub, now))
        assertNull(Updater.parseManifest("<html>not json</html>", 40, pub, now))
        assertNull(Updater.parseManifest("", 40, pub, now))
    }

    /** Audit M1/M2: nothing in the feed is believed unless the publisher signed it. */
    @Test fun onlyTheSignedStatementIsRead() {
        val (pub, sign) = publisher()
        val (otherPub, otherSign) = publisher()
        // The build-46 shape — unsigned fields only — offers nothing, whatever it claims.
        val unsigned = """{ "android": { "build": 9999, "version": "9", "url": "$repo/download/v9999/skwod-9999.apk",
            "sha256": "ab", "sig": "old", "sig2": "cd", "notes": "Install this from evil.example" } }"""
        assertNull(Updater.parseManifest(unsigned, 40, pub, now))
        assertFalse(Updater.isFresh(unsigned, pub, now))
        // Signed by someone else, or by nobody the build pins.
        assertNull(Updater.parseManifest(manifest(otherSign, statement()), 40, pub, now))
        assertNull(Updater.parseManifest(manifest(sign, statement()), 40, "", now))
        assertNull(Updater.parseManifest(manifest(sign, statement()), 40, nowSec = now))   // the pinned production key
        assertNotNull(Updater.parseManifest(manifest(otherSign, statement()), 40, otherPub, now))
        // The unsigned copy says something else (build 9999, other notes): the statement wins.
        val split = manifest(sign, statement(41, "real notes"), statement(9999, "phish"))
        val a = Updater.parseManifest(split, 40, pub, now)!!
        assertEquals(41, a.build); assertEquals("real notes", a.notes)
        // A statement edited after signing no longer verifies (the signature covers the exact bytes).
        val good = org.json.JSONObject(manifest(sign, statement()))
        val edited = String(Base64.getDecoder().decode(good.getString("signed"))).replace("\"build\":41", "\"build\":77")
        good.put("signed", Base64.getEncoder().encodeToString(edited.toByteArray()))
        assertNull(Updater.parseManifest(good.toString(), 40, pub, now))
        // A signature over the bare statement (no label) is not a manifest signature.
        val raw = statement().toByteArray()
        val unlabelled = org.json.JSONObject().put("signed", Base64.getEncoder().encodeToString(raw)).put("signed_sig", sign(raw))
        assertNull(Updater.parseManifest(unlabelled.toString(), 40, pub, now))
    }

    /** Audit M2: a frozen feed is noticed once its statement expires. */
    @Test fun anExpiredStatementIsStaleAndAPostDatedOneIsRefused() {
        val (pub, sign) = publisher()
        val body = manifest(sign, statement())
        assertTrue(Updater.isFresh(body, pub, now + 119 * 86400L))
        assertFalse(Updater.isFresh(body, pub, now + 120 * 86400L))
        // Expired but genuine and newer: still offered (an old real update beats none)…
        assertEquals(41, Updater.parseManifest(body, 40, pub, now + 400 * 86400L)!!.build)
        // …and "nothing newer" from an expired statement is not "up to date".
        assertNull(Updater.parseManifest(body, 41, pub, now + 400 * 86400L))
        assertTrue(Updater.verifiedStatement(body, pub, now + 400 * 86400L).let { it is Updater.Statement.Valid && it.expired })
        // Issued "in the future" beyond a day of skew, or with a nonsensical validity: refused.
        assertNotNull(Updater.parseManifest(manifest(sign, statement(issued = now + 3600)), 40, pub, now))
        assertNull(Updater.parseManifest(manifest(sign, statement(issued = now + 2 * 86400L)), 40, pub, now))
        assertNull(Updater.parseManifest(manifest(sign, statement(issued = now, expires = now)), 40, pub, now))
        assertNull(Updater.parseManifest(manifest(sign, statement().replace("\"v\":1", "\"v\":2")), 40, pub, now))
    }

    /** The fixture sign-manifest.sh wrote (throwaway key): script, Kotlin and Swift agree on the bytes. */
    @Test fun theScriptsFixtureVerifies() {
        val dir = generateSequence(File("").absoluteFile) { it.parentFile }.map { File(it, "tools/release/fixtures") }.firstOrNull { it.isDirectory }
        assumeTrue("tools/release/fixtures not found from ${File("").absolutePath}", dir != null)
        val body = File(dir, "manifest-v1.json").readText()
        val pub = File(dir, "manifest-v1.pub").readText().trim()
        val a = Updater.parseManifest(body, 45, pub, 1_800_000_060L)!!
        assertEquals(46, a.build)
        assertEquals("Fixes \"things\" & more.", a.notes)
        assertEquals("$repo/download/v46/skwod-46.apk", a.url)
        assertTrue(Updater.isFresh(body, pub, 1_800_000_060L))
        assertNull(Updater.parseManifest(body, 45, nowSec = 1_800_000_060L))    // not the production key
    }

    @Test fun apkInstallsOnlyWithThePublishersSignature() {
        val (pub, sign) = publisher()
        val bytes = ByteArray(4096) { (it * 31).toByte() }
        val apk = tempApk(bytes)
        fun info(sha: String?, sig: String?) = Updater.Available(41, "0.1.0", "", "$repo/download/v41/skwod-41.apk", sha, sig)
        val good = sign(Updater.signedMessage(41, sha256(bytes)))

        assertEquals(Updater.Verify.Ok, Updater.verifyDownload(apk, info(hex(sha256(bytes)), good), pub, 40))
        assertEquals(Updater.Verify.Ok, Updater.verifyDownload(apk, info(hex(sha256(bytes)).uppercase(), good), pub, 40))
        // No sha256 in the manifest: the signature alone still decides.
        assertEquals(Updater.Verify.Ok, Updater.verifyDownload(apk, info(null, good), pub, 40))

        // Missing / garbage / someone else's signature.
        assertEquals(Updater.Verify.Bad, Updater.verifyDownload(apk, info(hex(sha256(bytes)), null), pub, 40))
        assertEquals(Updater.Verify.Bad, Updater.verifyDownload(apk, info(hex(sha256(bytes)), ""), pub, 40))
        assertEquals(Updater.Verify.Bad, Updater.verifyDownload(apk, info(hex(sha256(bytes)), "not base64!!"), pub, 40))
        val (_, otherSign) = publisher()
        assertEquals(Updater.Verify.Bad, Updater.verifyDownload(apk, info(hex(sha256(bytes)), otherSign(Updater.signedMessage(41, sha256(bytes)))), pub, 40))
        // The pinned production key does not accept a signature from a throwaway key.
        assertEquals(Updater.Verify.Bad, Updater.verifyDownload(apk, info(hex(sha256(bytes)), good), installedBuild = 40))
        // No key pinned in the build: refuse.
        assertEquals(Updater.Verify.NotProvisioned, Updater.verifyDownload(apk, info(hex(sha256(bytes)), good), "", 40))

        // A swapped apk: with the old sha256 the checksum catches it; with a matching sha256 (the
        // attacker rewrote the manifest too) the signature does.
        val evil = tempApk(bytes.copyOf().also { it[0] = 1 })
        assertEquals(Updater.Verify.Checksum, Updater.verifyDownload(evil, info(hex(sha256(bytes)), good), pub, 40))
        assertEquals(Updater.Verify.Bad, Updater.verifyDownload(evil, info(hex(sha256(evil.readBytes())), good), pub, 40))
        assertEquals(Updater.Verify.Bad, Updater.verifyDownload(evil, info(null, good), pub, 40))
    }

    /** Audit L5: the build number is signed with the digest, and nothing not newer is installed. */
    @Test fun theSignatureBindsTheBuildNumberAndDowngradesAreRefused() {
        val (pub, sign) = publisher()
        val bytes = ByteArray(2048) { (it * 7).toByte() }
        val apk = tempApk(bytes)
        val digest = sha256(bytes)
        fun info(build: Int, sig: String?) = Updater.Available(build, "0.1.0", "", "$repo/download/v$build/skwod-$build.apk", hex(digest), sig)
        val sig46 = sign(Updater.signedMessage(46, digest))

        assertEquals(Updater.Verify.Ok, Updater.verifyDownload(apk, info(46, sig46), pub, 45))
        // The manifest claims another build for the same signed apk: the signature no longer fits.
        assertEquals(Updater.Verify.Bad, Updater.verifyDownload(apk, info(60, sig46), pub, 45))
        assertEquals(Updater.Verify.Bad, Updater.verifyDownload(apk, info(47, sig46), pub, 45))
        // The build-45 format — a signature over the digest alone — is not accepted for any build.
        assertEquals(Updater.Verify.Bad, Updater.verifyDownload(apk, info(46, sign(digest)), pub, 45))
        // Not newer than what is installed: refused whatever the signature says.
        assertEquals(Updater.Verify.Downgrade, Updater.verifyDownload(apk, info(46, sig46), pub, 46))
        assertEquals(Updater.Verify.Downgrade, Updater.verifyDownload(apk, info(46, sig46), pub, 47))
        assertEquals(Updater.Verify.Downgrade, Updater.verifyDownload(apk, info(44, sign(Updater.signedMessage(44, digest))), pub, 45))

        // The message is the label, the build in decimal, then the digest — what package-release.sh signs.
        assertEquals("skwod-android-update-v2\n46\n", String(Updater.signedMessage(46, digest).copyOf(27), Charsets.US_ASCII))
        assertTrue(Updater.signedMessage(46, digest).copyOfRange(27, 59).contentEquals(digest))

        // The downloaded apk must itself be that build of this app.
        assertTrue(Updater.archiveMatches("com.skwod.app", 46L, "com.skwod.app", 46))
        assertFalse(Updater.archiveMatches("com.skwod.app", 45L, "com.skwod.app", 46))
        assertFalse(Updater.archiveMatches("com.other", 46L, "com.skwod.app", 46))
        assertFalse(Updater.archiveMatches(null, null, "com.skwod.app", 46))
    }

    @Test fun dailyCheckIsDueOncePerDay() {
        val day = 24L * 60 * 60 * 1000
        val now = 1_800_000_000_000L
        assertTrue(Updater.due(0, now))                    // never checked
        assertFalse(Updater.due(now - day + 1, now))
        assertTrue(Updater.due(now - day, now))
        assertTrue(Updater.due(now + 5000, now))           // clock went backwards
    }

    /**
     * The REAL release, through the same code the app runs: `package-release.sh` sets
     * SKWOD_RELEASE_DIR to `releases/<build>` and runs this test, so a release whose manifest the
     * shipped app would reject never leaves the build machine. Skipped when the variable is unset.
     */
    @Test fun packagedReleaseVerifiesWithThePinnedKey() {
        val dir = System.getenv("SKWOD_RELEASE_DIR")
        assumeTrue("SKWOD_RELEASE_DIR not set", !dir.isNullOrEmpty())
        val manifest = File(dir, "manifest.json")
        assertTrue("missing ${manifest.path}", manifest.isFile)
        // Build 0 = "any build is newer": we are checking the artifact, not this checkout's version.
        val info = Updater.parseManifest(manifest.readText(), 0)
        assertNotNull("manifest has no android entry signed by the pinned key", info)
        assertTrue("the manifest's statement is expired or unsigned", Updater.isFresh(manifest.readText()))
        info!!
        assertTrue("apk url not in the release repo: ${info.url}", Updater.allowedStart(info.url))
        assertEquals("$repo/download/v${info.build}/skwod-${info.build}.apk", info.url)
        val apk = File(dir, info.url.substringAfterLast('/'))
        assertTrue("missing ${apk.path}", apk.isFile)
        assertNotNull("manifest has no sha256", info.sha256)
        assertEquals(Updater.Verify.Ok, Updater.verifyDownload(apk, info, installedBuild = 0))   // pinned production key
    }
}
