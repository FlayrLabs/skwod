package io.skwod.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Native in-app self-update. skwod is decentralized — most skwods are p2p and have no https address
 * — so updates do NOT come from the connected skwod. Every release is published to one public
 * place, the GitHub repo `FlayrLabs/skwod-releases` (binaries + feeds only), and every install
 * reads the same manifest: [MANIFEST_URL]. We compare it to [BuildConfig.VERSION_CODE] and, when
 * behind, offer a one-tap update: download the new `.apk`, verify a PUBLISHER signature over it,
 * then hand it to Android's package installer (the "Update this app?" sheet — Android always
 * requires that tap).
 *
 * TRUST MODEL (important — the app holds REQUEST_INSTALL_PACKAGES):
 * GitHub is a distribution channel, NOT a trust anchor. Authenticity comes from an independent
 * publisher signature: the release is signed on the release machine with an Ed25519 key GitHub never
 * sees, whose PUBLIC half is pinned into this binary ([UPDATE_PUBLIC_KEY_B64]). (That key is a file on
 * the build machine today, not a hardware token or an offline signer — RELEASE-SIGNING.md, "Known
 * operational risks".) Two things are signed with it:
 *
 *  1. THE MANIFEST. Everything this app believes about a release — build number, version, release
 *     notes, the apk's URL and digest, when the statement was issued and when it stops being fresh —
 *     is read from the manifest's `signed` statement, and only after `signed_sig` has verified over
 *     exactly those bytes ([verifiedStatement]). The unsigned `android` object next to it exists for
 *     earlier builds and is not read (one exception, [parseManifest]: a device that cannot verify
 *     Ed25519 takes the bare build number from it, so it can say "update from the download page").
 *     Whoever controls the repo can therefore not put words, links or version numbers in the
 *     update banner.
 *  2. THE APK. `sig2` (base64) is computed over the BUILD NUMBER together with the raw SHA-256
 *     digest of the apk ([signedMessage]).
 * Whoever controls the repo, the CDN or the network can at most withhold an update — never get one
 * installed, and never pass one build off as another: the build the manifest names is the build
 * that was signed, a build that is not newer than this install is refused before and after the
 * download, and the downloaded apk's own versionCode must be that build ([archiveMatches]). This
 * mirrors the macOS build's EdDSA-signed Sparkle appcast. The SHA-256 remains only as a cheap
 * integrity pre-check that binds the signed digest to the file on disk. Android itself refuses an
 * apk whose signing certificate differs from the installed app's, or whose versionCode is lower.
 *
 * (`sig`, the build-45-and-older signature over the digest alone, is still written to the manifest
 * for those installs. This build ignores it: a manifest with only `sig` is refused.)
 *
 * FRESHNESS (bounded, not solved): the statement carries `issued` and `expires` (120 days by
 * default). Whoever controls the repo can still keep serving an older signed manifest — a freeze —
 * but only until it expires: after that [feedStale] is set and a manual check says that this app
 * can no longer tell whether it is up to date, instead of "you're up to date". A statement that
 * is genuine and names a newer build is still offered after it expired (an old real update beats
 * none). A statement dated in the future beyond a day of clock skew is refused.
 *
 * TRANSPORT: `https://` only, and only to GitHub. Requests start at `github.com` under the release
 * repo's path; GitHub answers with redirects to its asset host, which we follow BY HAND and only to
 * the hosts in [REDIRECT_HOSTS], re-validating scheme, host and port on every hop ([nextHop]).
 *
 * PRIVACY: a check is one anonymous GET of a public file — no account, device id or skwod address
 * is sent — but GitHub necessarily sees the device's IP address. Automatic checks run at most once
 * a day and can be turned off (Settings → "Check for updates automatically"); see docs/SECURITY.md.
 */
object Updater {
    /** The one manifest every install reads: the newest release's `manifest.json`. */
    const val MANIFEST_URL = "https://github.com/FlayrLabs/skwod-releases/releases/latest/download/manifest.json"
    /** Everything we ask GitHub for lives under this path of `github.com` (the release repo). */
    private const val RELEASE_PATH = "/FlayrLabs/skwod-releases/releases/"

    /**
     * The only hosts a request may START at or be REDIRECTED to. `github.com` serves
     * `releases/latest/download/<f>` → 302 `releases/download/<tag>/<f>` → 302 to its asset host.
     * That host is `release-assets.githubusercontent.com` (observed 2026-11-18);
     * `objects.githubusercontent.com` is the one GitHub used before it.
     */
    internal val REDIRECT_HOSTS = setOf("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")
    private const val MAX_REDIRECTS = 5
    private const val MAX_MANIFEST_BYTES = 64 * 1024
    private const val DAY_MS = 24L * 60 * 60 * 1000

    /**
     * Pinned Ed25519 PUBLIC key of the release publisher (standard base64, NO wrap). Accepts either a
     * bare 32-byte key or a full X.509/SPKI encoding. EMPTY = signing not yet provisioned, in which
     * case in-app install is refused (fail closed) rather than trusting an unsigned apk.
     *
     * The private half never goes to GitHub; it is restored onto the release machine from the
     * maintainers' secret store (RELEASE-SIGNING.md — it is NOT yet on a hardware token or an offline
     * machine). package-release.sh signs the manifest statement ([verifiedStatement]) and
     * [signedMessage] (build number + `SHA256(apk)`) with it.
     */
    private const val UPDATE_PUBLIC_KEY_B64 = "4Sh3oT9eIwxDNLwUYUnZbaGm2lt0jEnBT2EYzGx5pY8="

    /** SPKI (X.509) DER header for an Ed25519 public key — prepended to a bare 32-byte key. */
    private val ED25519_SPKI_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    )

    /** Outcome of the publisher-signature gate, each with a user-facing message. */
    internal enum class Verify(val message: String) {
        Ok(""),
        NotProvisioned("In-app updates aren't available yet — grab the latest build from the download page."),
        Unsupported("This device can't verify update signatures — update from the download page instead."),
        Bad("This update failed its publisher signature check and was not installed."),
        Checksum("Downloaded update failed its checksum. Not installing."),
        Downgrade("This update is not newer than the installed build and was not installed."),
    }
    data class Available(
        val build: Int,
        val version: String,
        val notes: String,
        /** Where the apk is: an https URL under the release repo on github.com (validated). */
        val url: String,
        val sha256: String?,
        /** Base64 Ed25519 publisher signature over [signedMessage] (manifest field `sig2`). */
        val sig: String?,
    )

    sealed interface Phase {
        data object Idle : Phase
        data object Checking : Phase
        data class Downloading(val pct: Int) : Phase
        data object Installing : Phase
        data class Failed(val msg: String) : Phase
    }

    var available by mutableStateOf<Available?>(null); private set
    var phase by mutableStateOf<Phase>(Phase.Idle); private set
    /** True once the user has hit "Check for updates" so the UI can say "up to date" vs staying silent. */
    var lastCheckManual by mutableStateOf(false); private set

    /** Whether the last [check] got an answer from the feed at all (as opposed to "no network"). */
    @Volatile private var reachedFeed = false

    /**
     * The last manifest read was not a fresh, validly signed statement: it had expired, or carried
     * no statement this build accepts. "No update" then does not mean "up to date".
     */
    var feedStale by mutableStateOf(false); private set
    internal const val STALE_MESSAGE = "Couldn't confirm this is the latest build: the update feed is out of date or not signed. Check skwod.io."

    /**
     * Fetch the release manifest and, if it advertises a newer android build, populate [available].
     * Silent on failure — a version check must never disrupt the app. Returns the newer build, if any.
     */
    suspend fun check(manual: Boolean = false): Available? {
        lastCheckManual = manual
        if (manual) phase = Phase.Checking
        val body = withContext(Dispatchers.IO) {
            try {
                open(MANIFEST_URL, 10000)?.let { c ->
                    try { readCapped(c.inputStream, MAX_MANIFEST_BYTES) } finally { c.disconnect() }
                }
            } catch (_: Exception) { null }
        }
        reachedFeed = body != null
        val found = body?.let { parseManifest(it, BuildConfig.VERSION_CODE) }
        available = found
        feedStale = body != null && !isFresh(body)
        if (manual) phase = if (found == null && feedStale) Phase.Failed(STALE_MESSAGE) else Phase.Idle
        return found
    }

    /**
     * The automatic check: at most once a day, and only while the user has it switched on. Called
     * from a process-wide ticker ([startAutomaticChecks]) and whenever the app comes to the front.
     * The process stays alive in the background through [ConnectionService], so this needs no
     * WorkManager / Play Services scheduler. A newer build raises ONE "Update available"
     * notification per build; installing still takes the user's tap.
     *
     * While a newer build is already known, opening the app asks again regardless of the daily
     * limit, so the banner is there when the notification is tapped after the process was killed.
     */
    suspend fun autoCheck(ctx: Context, foreground: Boolean = false) {
        val settings = AppSettings.get(ctx)
        if (!settings.autoUpdateCheck) return
        val now = System.currentTimeMillis()
        val pending = foreground && available == null && settings.updateKnownBuild > BuildConfig.VERSION_CODE
        if (!pending && !due(settings.updateLastCheck, now)) return
        val found = check()
        // A check that never reached the feed (offline, GitHub down) doesn't use up the day: the
        // hourly ticker tries again.
        if (reachedFeed) settings.updateLastCheck = now
        if (found == null) return
        settings.updateKnownBuild = found.build
        if (settings.updateNotifiedBuild != found.build) {
            settings.updateNotifiedBuild = found.build
            Notifications.updateAvailable(ctx, found.version, found.build)
        }
    }

    /** True when a daily check is due (also after the clock was set back). */
    internal fun due(last: Long, now: Long): Boolean = last <= 0L || now - last >= DAY_MS || now < last

    @Volatile private var ticker: kotlinx.coroutines.Job? = null

    /** Start the daily ticker once per process. Cheap: it wakes hourly and usually does nothing. */
    fun startAutomaticChecks(ctx: Context) {
        val app = ctx.applicationContext
        synchronized(this) {
            if (ticker != null) return
            ticker = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + Dispatchers.IO).launch {
                while (true) {
                    try { autoCheck(app) } catch (_: Exception) {}
                    kotlinx.coroutines.delay(60L * 60 * 1000)
                }
            }
        }
    }

    /** Label under which the publisher signs the manifest statement (never used for anything else). */
    internal const val STATEMENT_LABEL = "skwod-release-manifest-v1\n"
    /** A statement "issued" further in the future than this is refused (clock skew allowance). */
    private const val MAX_SKEW_SEC = 24L * 60 * 60
    private const val MAX_STATEMENT_BYTES = 16 * 1024

    /** What [verifiedStatement] made of a manifest. */
    internal sealed interface Statement {
        /** Signed by the pinned key. [expired] = past its `expires`. */
        data class Valid(val json: JSONObject, val expired: Boolean) : Statement
        /** No statement, a bad signature, a malformed or post-dated one. Nothing in it is used. */
        data object Invalid : Statement
        /** This device has no Ed25519 verifier (Android < 13). Nothing can be authenticated. */
        data object Unsupported : Statement
    }

    /**
     * The manifest's signed statement: `signed` (base64 JSON) is used only if `signed_sig` is the
     * pinned publisher's Ed25519 signature over [STATEMENT_LABEL] + exactly those bytes. The bytes
     * are parsed AFTER they verified, never before, and nothing outside them is trusted.
     */
    internal fun verifiedStatement(body: String, pubKeyB64: String = UPDATE_PUBLIC_KEY_B64, nowSec: Long = System.currentTimeMillis() / 1000): Statement {
        if (pubKeyB64.isBlank()) return Statement.Invalid
        val (raw, sig) = try {
            val root = JSONObject(body)
            val dec = java.util.Base64.getDecoder()
            dec.decode(root.getString("signed")) to dec.decode(root.getString("signed_sig"))
        } catch (_: Exception) { return Statement.Invalid }
        if (raw.isEmpty() || raw.size > MAX_STATEMENT_BYTES || sig.size != 64) return Statement.Invalid
        val verifier = try { Signature.getInstance("Ed25519") } catch (_: Exception) { return Statement.Unsupported }
        return try {
            val key = java.util.Base64.getDecoder().decode(pubKeyB64)
            val spki = if (key.size == 32) ED25519_SPKI_PREFIX + key else key
            verifier.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki)))
            verifier.update(STATEMENT_LABEL.toByteArray(Charsets.US_ASCII) + raw)
            if (!verifier.verify(sig)) return Statement.Invalid
            val json = JSONObject(String(raw, Charsets.UTF_8))
            val issued = json.getLong("issued")
            val expires = json.getLong("expires")
            if (json.getInt("v") != 1 || issued >= expires || issued > nowSec + MAX_SKEW_SEC) return Statement.Invalid
            Statement.Valid(json, expired = nowSec >= expires)
        } catch (_: Exception) { Statement.Invalid }
    }

    /** True when [body] carries a validly signed statement that has not expired. */
    internal fun isFresh(body: String, pubKeyB64: String = UPDATE_PUBLIC_KEY_B64, nowSec: Long = System.currentTimeMillis() / 1000): Boolean =
        (verifiedStatement(body, pubKeyB64, nowSec) as? Statement.Valid)?.expired == false

    /**
     * The release this manifest offers Android, as an [Available] — or null when there is none, it
     * is not newer, or the manifest is not signed by the publisher. Every field comes from the
     * SIGNED statement. The unsigned `android` object (what earlier builds read) is ignored, with
     * one exception: on a device that cannot verify Ed25519 at all, its bare build number is taken
     * so the app can still say "a newer build exists — get it from the download page". No text,
     * version string or URL is taken from it, and [install] then refuses ([Verify.Unsupported]).
     */
    internal fun parseManifest(body: String, currentBuild: Int, pubKeyB64: String = UPDATE_PUBLIC_KEY_B64, nowSec: Long = System.currentTimeMillis() / 1000): Available? {
        val entry = when (val st = verifiedStatement(body, pubKeyB64, nowSec)) {
            is Statement.Valid -> st.json.optJSONObject("android") ?: return null
            Statement.Invalid -> return null
            Statement.Unsupported -> {
                val build = try { JSONObject(body).optJSONObject("android")?.optInt("build", 0) ?: 0 } catch (_: Exception) { 0 }
                return if (build > currentBuild) Available(build, build.toString(), "", "", null, null) else null
            }
        }
        val build = entry.optInt("build", 0)
        if (build <= currentBuild) return null
        return Available(
            build = build,
            version = entry.optString("version", build.toString()).take(40),
            notes = entry.optString("notes", "").take(500),
            url = entry.optString("url", ""),
            sha256 = entry.optString("sha256", "").ifEmpty { null },
            // Only the build-bound signature. The older `sig` (digest alone) is not read.
            sig = entry.optString("sig2", "").ifEmpty { null },
        )
    }

    // ---- transport: https to GitHub only, redirects followed by hand ----

    /** A URL we may send a request to at all: https, an allowlisted host, default port, no credentials. */
    internal fun allowedHost(url: String): Boolean = try {
        val u = java.net.URI(url)
        u.scheme.equals("https", ignoreCase = true) && u.host != null &&
            u.host.lowercase() in REDIRECT_HOSTS && (u.port == -1 || u.port == 443) && u.userInfo == null
    } catch (_: Exception) { false }

    /**
     * A URL a request may START at: `github.com`, a plain file path inside the release repo, no
     * query or fragment. (The apk URL comes from the manifest, so it is held to this too.)
     */
    internal fun allowedStart(url: String): Boolean = try {
        val u = java.net.URI(url)
        allowedHost(url) && u.host.equals("github.com", ignoreCase = true) &&
            START_PATH.matches(u.rawPath ?: "") && !u.rawPath.contains("..") &&
            u.rawQuery == null && u.rawFragment == null
    } catch (_: Exception) { false }
    private val START_PATH = Regex("^" + Regex.escape(RELEASE_PATH) + "[A-Za-z0-9._/-]{1,200}$")

    /**
     * Where a redirect from [current] with the given `Location` header leads, or null when it must
     * not be followed. Relative locations are resolved first; the result is then held to exactly the
     * same rule as any other hop, so a redirect can never downgrade to http or leave the allowlist.
     */
    internal fun nextHop(current: String, location: String?): String? {
        if (location.isNullOrBlank()) return null
        val next = try { java.net.URI(current).resolve(location.trim()).toString() } catch (_: Exception) { return null }
        return if (allowedHost(next)) next else null
    }

    /** One response, as far as redirect handling cares. */
    internal data class Hop(val code: Int, val location: String?)

    /**
     * Walk the redirect chain from [start], asking [fetch] for each URL in turn. Returns the URL
     * that answered 200, or null: on any other status, a hop outside the allowlist, a loop, or more
     * than [MAX_REDIRECTS] redirects. [fetch] is never called with a URL that isn't allowed.
     */
    internal fun resolve(start: String, fetch: (String) -> Hop): String? {
        if (!allowedStart(start)) return null
        var url = start
        repeat(MAX_REDIRECTS + 1) {
            val hop = fetch(url)
            when (hop.code) {
                200 -> return url
                301, 302, 303, 307, 308 -> url = nextHop(url, hop.location) ?: return null
                else -> return null
            }
        }
        return null
    }

    /** GET [start], following allowlisted redirects. The returned connection answered 200. */
    private fun open(start: String, readTimeoutMs: Int): javax.net.ssl.HttpsURLConnection? {
        var live: javax.net.ssl.HttpsURLConnection? = null
        val reached = resolve(start) { url ->
            val c = java.net.URL(url).openConnection() as javax.net.ssl.HttpsURLConnection
            c.connectTimeout = 10000; c.readTimeout = readTimeoutMs
            c.instanceFollowRedirects = false            // every hop goes through nextHop()
            c.useCaches = false
            val code = c.responseCode
            val location = c.getHeaderField("Location")
            if (code == 200) live = c else c.disconnect()
            Hop(code, location)
        }
        return if (reached != null) live else null
    }

    private fun readCapped(input: java.io.InputStream, max: Int): String = input.use { s ->
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (true) {
            val n = s.read(buf); if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > max) throw java.io.IOException("too large")
        }
        out.toString("UTF-8")
    }

    /**
     * Download the update apk, verify the publisher signature over it, and launch the system
     * installer. On Android 8+ the app needs the "install unknown apps" permission for its own
     * package; if it's not granted we send the user straight to that settings screen (they return and
     * tap Update again). An apk that fails integrity or the publisher-signature gate is deleted and
     * never handed to the installer.
     */
    suspend fun install(ctx: Context) {
        val info = available ?: return
        // A device without an Ed25519 verifier learned only the build number (parseManifest).
        if (info.url.isEmpty() && info.sig == null) { phase = Phase.Failed(Verify.Unsupported.message); return }
        // Even a signed apk URL may only name a file in the release repo.
        if (!allowedStart(info.url)) { phase = Phase.Failed("This update has no valid Android download. Not installing."); return }
        // Fail closed BEFORE downloading anything when there is no signature to check.
        if (info.sig.isNullOrBlank()) { phase = Phase.Failed(Verify.Bad.message); return }

        // Gate: without permission the installer intent silently no-ops, so ask up front.
        if (!ctx.packageManager.canRequestPackageInstalls()) {
            phase = Phase.Failed("Allow installs from Skwod, then tap Update again.")
            val i = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${ctx.packageName}"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            runCatching { ctx.startActivity(i) }
            return
        }

        val apk = withContext(Dispatchers.IO) {
            try {
                val dir = File(ctx.cacheDir, "skwod-updates").apply { mkdirs() }
                // Clear stale downloads so we never install an old file by mistake.
                dir.listFiles()?.forEach { it.delete() }
                val out = File(dir, "skwod-${info.build}.apk")
                val c = open(info.url, 60000) ?: return@withContext null
                val total = c.contentLengthLong
                var read = 0L
                phase = Phase.Downloading(0)
                try {
                    c.inputStream.use { input ->
                        out.outputStream().use { output ->
                            val buf = ByteArray(1 shl 16)
                            while (true) {
                                val n = input.read(buf); if (n < 0) break
                                output.write(buf, 0, n); read += n
                                if (read > MAX_APK_BYTES) throw java.io.IOException("too large")
                                if (total > 0) phase = Phase.Downloading((read * 100 / total).toInt())
                            }
                        }
                    }
                } finally { c.disconnect() }
                out
            } catch (_: Exception) { null }
        } ?: run { phase = Phase.Failed("Download failed — check your connection."); return }

        // Integrity + authenticity over the bytes on disk; anything but Ok deletes the file.
        when (val v = withContext(Dispatchers.IO) { verifyDownload(apk, info) }) {
            Verify.Ok -> {}
            else -> { apk.delete(); phase = Phase.Failed(v.message); return }
        }
        // The signature says "build N has this digest". The apk must BE build N (and this app).
        val archive = withContext(Dispatchers.IO) { runCatching { ctx.packageManager.getPackageArchiveInfo(apk.path, 0) }.getOrNull() }
        @Suppress("DEPRECATION")
        val archiveBuild = archive?.let { if (android.os.Build.VERSION.SDK_INT >= 28) it.longVersionCode else it.versionCode.toLong() }
        if (!archiveMatches(archive?.packageName, archiveBuild, ctx.packageName, info.build)) {
            apk.delete(); phase = Phase.Failed(Verify.Bad.message); return
        }

        phase = Phase.Installing
        val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.fileprovider", apk)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            if (ctx !is Activity) addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        runCatching { ctx.startActivity(intent) }
            .onFailure { phase = Phase.Failed("Couldn't open the installer.") }
    }

    private fun sha256Bytes(f: File): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { s ->
            val buf = ByteArray(1 shl 16)
            while (true) { val n = s.read(buf); if (n < 0) break; md.update(buf, 0, n) }
        }
        return md.digest()
    }

    /**
     * Both gates over a downloaded apk, computing its digest ONCE:
     *   1) integrity    — the digest must match the manifest's advertised sha256 (binds the signed
     *                     digest to the exact bytes on disk; NOT an authenticity control on its own).
     *   2) authenticity — a valid publisher Ed25519 signature over the build number and that
     *                     digest (the real gate).
     * Before either: a build that is not newer than [installedBuild] is refused outright.
     */
    internal fun verifyDownload(apk: File, info: Available, pubKeyB64: String = UPDATE_PUBLIC_KEY_B64, installedBuild: Int = BuildConfig.VERSION_CODE): Verify {
        if (info.build <= installedBuild) return Verify.Downgrade
        val digest = sha256Bytes(apk)
        info.sha256?.let { expected ->
            val gotHex = digest.joinToString("") { "%02x".format(it) }
            if (!gotHex.equals(expected, ignoreCase = true)) return Verify.Checksum
        }
        return verifyPublisher(digest, info.build, info.sig, pubKeyB64)
    }

    /**
     * What the publisher signs for an Android release: a fixed label, the build number in decimal,
     * and the apk's raw SHA-256 digest. The label keeps this signature from ever being mistaken for
     * the older one over the bare digest, or for anything else the key might sign.
     */
    internal fun signedMessage(build: Int, digest: ByteArray): ByteArray =
        "skwod-android-update-v2\n$build\n".toByteArray(Charsets.US_ASCII) + digest

    /** The downloaded apk is this app, at exactly the build the manifest (and the signature) named. */
    internal fun archiveMatches(archivePackage: String?, archiveBuild: Long?, ourPackage: String, offeredBuild: Int): Boolean =
        archivePackage == ourPackage && archiveBuild == offeredBuild.toLong()

    /**
     * The authenticity gate: verify the pinned publisher's Ed25519 signature over [signedMessage] —
     * the [build] number and the apk's SHA-256 [digest]. Fail closed on every uncertainty — no pinned key, no/invalid signature, or a platform
     * that can't do Ed25519 all REFUSE the install rather than trusting downloaded bytes.
     *
     * Uses the platform provider's "Ed25519" (available from API 33 / Android 13). On older devices we
     * have no vetted verifier in-app, so we refuse the in-app install and point the user at a manual
     * download rather than shipping hand-rolled crypto or silently trusting an unsigned apk.
     */
    internal fun verifyPublisher(digest: ByteArray, build: Int, sigB64: String?, pubKeyB64: String = UPDATE_PUBLIC_KEY_B64): Verify {
        if (pubKeyB64.isBlank()) return Verify.NotProvisioned
        if (sigB64.isNullOrBlank()) return Verify.Bad
        val verifier = try { Signature.getInstance("Ed25519") } catch (_: Exception) { return Verify.Unsupported }
        return try {
            val raw = java.util.Base64.getDecoder().decode(pubKeyB64)
            val spki = if (raw.size == 32) ED25519_SPKI_PREFIX + raw else raw
            val pub = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki))
            val sig = java.util.Base64.getDecoder().decode(sigB64)
            verifier.initVerify(pub)
            verifier.update(signedMessage(build, digest))
            if (verifier.verify(sig)) Verify.Ok else Verify.Bad
        } catch (_: Exception) {
            // Any parsing/provider failure is treated as a failed check — never as "assume valid".
            Verify.Bad
        }
    }

    /** Upper bound on an update download (a release apk is ~60 MB). */
    private const val MAX_APK_BYTES = 400L * 1024 * 1024
}
