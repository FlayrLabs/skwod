package io.skwod.app

import android.content.Context
import androidx.compose.runtime.Composable

/**
 * The paywall seam, default variant: there is no paywall. Nothing checks billing and nothing gates
 * the app. A build made with `-Pskwod.paywall=true` compiles `src/paywall` instead of this source
 * set (see app/build.gradle.kts).
 */
object PaywallGate {
    /** Appended to the sign-up hint on the auth screen: nothing to say without a paywall. */
    const val SIGNUP_NOTE = ""

    @Suppress("UNUSED_PARAMETER")
    fun entitled(ctx: Context): Boolean = true

    /** Never shown: [entitled] is always true. */
    @Suppress("UNUSED_PARAMETER")
    @Composable
    fun Screen(onRefresh: () -> Unit, onSignOut: () -> Unit) {}
}
