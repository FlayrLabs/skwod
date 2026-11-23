import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Release signing config, loaded from apps/android/keystore.properties (kept out of source control).
// A STABLE release key is required for the native self-update to work: Android refuses an update apk
// whose signature differs from the installed app, so every distributed build must use this same key.
val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) keystorePropsFile.inputStream().use { load(it) }
}

val paywall = (project.findProperty("skwod.paywall") as String?) == "true"
if (paywall) require(file("src/paywall/java").isDirectory) {
    "-Pskwod.paywall=true needs app/src/paywall, which is not part of this source tree"
}

android {
    namespace = "io.skwod.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.skwod.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 48   // bump on every new build; mirrors iOS CURRENT_PROJECT_VERSION
        versionName = "0.48"
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a") }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // Paywall: OFF by default — nothing checks billing and nothing gates the app (same as the
        // Apple build's SKWOD_PAYWALL flag). `./gradlew assembleRelease -Pskwod.paywall=true` turns
        // the Play-subscription gate on. The pricing model is not settled; leave it off.
        buildConfigField("boolean", "SKWOD_PAYWALL", paywall.toString())
    }

    // The paywall code is its own source set, so the app compiles with that directory absent:
    // src/paywall (Play subscription gate) with -Pskwod.paywall=true, src/nopaywall (a gate that
    // never gates) otherwise. Both define `PaywallGate`, the only name the rest of the app uses.
    sourceSets.getByName("main").java.srcDir(if (paywall) "src/paywall/java" else "src/nopaywall/java")

    signingConfigs {
        create("release") {
            if (keystorePropsFile.exists()) {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            // R8 code shrinking + obfuscation. Keep rules live in proguard-rules.pro (JNA/uniffi FFI,
            // Tink/EncryptedSharedPreferences, and reflection-touched models are kept there).
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Only sign with the release key when the keystore is present (CI/dev without it still builds).
            if (keystorePropsFile.exists()) signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true; buildConfig = true }   // BuildConfig.DEBUG gates the dev unlock
    packaging { resources.excludes += "/META-INF/{AL2.0,LGPL2.1}" }
    lint {
        // The tree has long-standing style findings; fail the build only on real errors.
        abortOnError = true
        checkReleaseBuilds = false
        warningsAsErrors = false
    }
    testOptions { unitTests.isReturnDefaultValues = true }
}

// package-release.sh points SKWOD_RELEASE_DIR at the packaged release and runs UpdaterTest against
// it; that input lives outside the project, so such a run must never be skipped as up-to-date.
tasks.withType<Test>().configureEach {
    val releaseDir = System.getenv("SKWOD_RELEASE_DIR") ?: ""
    inputs.property("skwodReleaseDir", releaseDir)
    outputs.upToDateWhen { releaseDir.isEmpty() }
}

dependencies {
    implementation(project(":core"))
    implementation(platform("androidx.compose:compose-bom:2024.09.03"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-process:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    // Pinned explicitly. NOTE: androidx.security:security-crypto is stuck on an ALPHA (1.1.0-alpha06)
    // and is effectively unmaintained by Google — EncryptedSharedPreferences/MasterKey are deprecated
    // upstream. Track it and plan a migration (e.g. to Tink directly or Jetpack DataStore + Tink) but
    // do NOT float the version: an accidental bump could silently change the at-rest key scheme.
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.1")   // WebSocket relay (realtime presence + notifications)
    implementation("io.livekit:livekit-android:2.27.0")    // WebRTC SFU client for E2EE voice/video
    constraints {
        // livekit-android 2.27.0 resolves protobuf-javalite 3.22.0, which has CVE-2024-7254
        // (stack overflow parsing deeply nested groups — reachable from a hostile SFU's signalling).
        // Same 3.x runtime line, patched; drop this once LiveKit's own requirement is >= 3.25.5.
        implementation("com.google.protobuf:protobuf-javalite:3.25.9") { because("CVE-2024-7254") }
    }
    // QR: scanning (invites, device-link codes) and drawing. CameraX for the preview/frames, ZXing's
    // pure-Java decoder for the code — fully offline, NO Google Play Services / ML Kit dependency.
    implementation("androidx.camera:camera-camera2:1.3.4")
    implementation("androidx.camera:camera-lifecycle:1.3.4")
    implementation("androidx.camera:camera-view:1.3.4")
    implementation("com.google.zxing:core:3.5.4")

    testImplementation("junit:junit:4.13.2")
    // The real org.json for JVM unit tests (android.jar only has throwing stubs): the updater's
    // manifest parsing is tested as shipped. Test classpath only — nothing is added to the app.
    testImplementation("org.json:json:20240303")

    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}
