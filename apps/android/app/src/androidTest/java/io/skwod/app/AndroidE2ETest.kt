package io.skwod.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.skwod_core.SkwodClient
import uniffi.skwod_core.signup
import java.io.File

/**
 * Drives the real Rust core (over JNI, with its tokio runtime) against a test server from the
 * Android emulator — the definitive proof that the Android FFI + async + network stack works, end
 * to end. Mirrors the Rust `dm_e2e` / `group_e2e` examples on-device.
 */
@RunWith(AndroidJUnit4::class)
class AndroidE2ETest {

    /**
     * The server under test, passed on the command line — there is no default, so running the
     * instrumented tests never contacts anyone's real skwod:
     * `./gradlew connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.skwodServer=https://…`
     * (the server must allow open signup, `SKWOD_OPEN_SIGNUP=1`). Skipped when not given.
     */
    private val base: String by lazy {
        val arg = androidx.test.platform.app.InstrumentationRegistry.getArguments().getString("skwodServer")
        org.junit.Assume.assumeTrue("pass -Pandroid.testInstrumentationRunnerArguments.skwodServer=…", !arg.isNullOrBlank())
        arg!!
    }

    @Test
    fun signup_device_dm_and_channel_round_trip() = runBlocking {
        val stamp = (System.currentTimeMillis() and 0xFFFF).toString()
        val aUser = "and$stamp"

        // 1) Account signup (PQXDH identity is created on-device at registerDevice).
        // Empty join code — the test server allows open signup.
        val a = signup(base, aUser, "e2e-strong-pw-123", "")
        assertTrue(a.userId.isNotEmpty())
        assertTrue(a.token.length > 20)

        // 2) Bind a client with the encrypted cache + register a device (publishes prekeys).
        val cacheFile = File.createTempFile("skwod-and", ".sqlite3").absolutePath
        val client = SkwodClient(base, a.token)
        val restored = client.attachCache(cacheFile, "ab".repeat(32))
        assertEquals(false, restored)
        val deviceId = client.registerDevice()
        assertTrue(deviceId.isNotEmpty())

        // 3) Create an E2EE space (server + channel with encrypted names) + post a channel message.
        val space = client.createSpace("Android Crew $stamp", "general")
        assertTrue(space.serverId.isNotEmpty())
        assertTrue(space.inviteCode.isNotEmpty())
        val mid = client.sendChannelMessage(space.channelId, "hello from android")
        assertTrue(mid.isNotEmpty())

        // 4) Persistence: own channel message survives a rebuild from the cache.
        val relaunched = SkwodClient(base, a.token)
        assertTrue(relaunched.attachCache(cacheFile, "ab".repeat(32)))
        val history = relaunched.history("channel:${space.channelId}")
        assertTrue(history.any { it.content == "hello from android" && it.authorId == "__me__" })
    }
}
