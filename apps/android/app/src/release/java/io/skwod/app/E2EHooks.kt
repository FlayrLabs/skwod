package io.skwod.app

/**
 * Release builds have no automation hooks: this stub replaces `src/debug/.../E2EHooks.kt`, so
 * none of that code (or the system properties it reads) exists in a shipped apk.
 */
object E2E {
    fun credentials(): Pair<String, String>? = null
    fun wantsCamera(): Boolean = false
    suspend fun drive(model: AppModel, ctx: android.content.Context) {}
    fun sawOutbox(sent: Int, pending: Int, failed: Int) {}
    fun sawReport(id: String, sealed: Boolean) {}
    fun suppressRecoveryPrompt(): Boolean = false
}
