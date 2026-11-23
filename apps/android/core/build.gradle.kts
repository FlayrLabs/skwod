plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.skwod.core"
    compileSdk = 35
    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    sourceSets["main"].manifest.srcFile("src/main/AndroidManifest.xml")
    lint {
        // This module is ONLY the generated UniFFI bindings. They reference java.lang.ref.Cleaner
        // (API 33) behind a runtime class check and fall back to a JNA cleaner on older releases,
        // which lint's static NewApi check cannot see.
        disable += "NewApi"
    }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    implementation("net.java.dev.jna:jna:5.13.0@aar")
}
