# skwod Android — R8/ProGuard keep rules.
#
# Conservative on purpose: the things kept here are all reached by reflection / JNI / native code,
# where R8's static analysis can't see the use and stripping or renaming them would break the app at
# runtime (crash on FFI call, or corrupt at-rest crypto). Everything else is free to be shrunk/renamed.

# ------------------------------------------------------------------------------------------------
# JNA (net.java.dev.jna) — the Rust core is called over JNA. JNA maps native memory to Java fields
# BY REFLECTION using declared field order (@Structure.FieldOrder / @JvmField), so Structure classes,
# their fields, and JNA's own callback/library interfaces must survive shrinking AND obfuscation.
# ------------------------------------------------------------------------------------------------
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }
-keep class * implements com.sun.jna.Library { *; }
-keep class * implements com.sun.jna.Callback { *; }
# JNA references java.awt.* which doesn't exist on Android — silence the resulting warnings.
-dontwarn java.awt.**

# ------------------------------------------------------------------------------------------------
# uniffi-generated FFI bindings for the Rust core (package uniffi.skwod_core). These declare JNA
# Structure subclasses (RustBuffer, ForeignBytes, …), UniffiLib native-method interfaces and callback
# structs that are wired up reflectively/natively. Keep the whole generated surface.
# ------------------------------------------------------------------------------------------------
-keep class uniffi.skwod_core.** { *; }
-keepclassmembers class uniffi.skwod_core.** { *; }

# ------------------------------------------------------------------------------------------------
# Tink + Jetpack Security (EncryptedSharedPreferences / MasterKey back the encrypted secrets store).
# Tink resolves key managers and parses protobuf key material reflectively; stripping it corrupts the
# at-rest token/key storage. Keep Tink and the security-crypto surface.
# ------------------------------------------------------------------------------------------------
-keep class com.google.crypto.tink.** { *; }
-keepclassmembers class com.google.crypto.tink.** { *; }
-dontwarn com.google.crypto.tink.**
-keep class androidx.security.crypto.** { *; }
# Tink pulls in protobuf-lite + optional providers/annotations that aren't all present at build time.
-dontwarn com.google.protobuf.**
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**

# ------------------------------------------------------------------------------------------------
# App models. The app (de)serializes these to/from JSON by hand via org.json, so field NAMES are not
# reflected on — but keeping them is cheap insurance against any future reflective/serialized use and
# keeps stack traces legible. Kept generously per the security-audit guidance.
# ------------------------------------------------------------------------------------------------
-keep class io.skwod.app.Workspace { *; }
-keep class io.skwod.app.ChatAttachment { *; }
-keep class io.skwod.app.MusicTrack { *; }
-keepclassmembers class io.skwod.app.** {
    <init>(...);
}

# ------------------------------------------------------------------------------------------------
# Ed25519 update-signature verification uses java.security via the platform Conscrypt provider on
# API 33+. Nothing app-side to keep, but silence provider-related warnings if they surface.
# ------------------------------------------------------------------------------------------------
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**

# OkHttp (WebSocket relay) ships its own consumer rules; just silence its optional-dep warnings.
-dontwarn okhttp3.**
-dontwarn okio.**

# LiveKit + WebRTC (E2EE voice/video). The AARs ship consumer rules, but keep the JNI-bound WebRTC
# classes and LiveKit's reflectively-touched types explicitly, and silence optional-dep warnings.
-keep class org.webrtc.** { *; }
-keep class livekit.org.webrtc.** { *; }
-keep class io.livekit.android.** { *; }
-keep class livekit.** { *; }
-dontwarn io.livekit.**
-dontwarn livekit.**

# ------------------------------------------------------------------------------------------------
# No logging in release. The app itself calls android.util.Log nowhere, but dependencies do (and a
# stray debug line must never ship message content, ids, host keys or addresses). R8 removes every
# call — including the argument evaluation — when told the methods have no side effects.
# ------------------------------------------------------------------------------------------------
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
    public static boolean isLoggable(java.lang.String, int);
    public static java.lang.String getStackTraceString(java.lang.Throwable);
    public static int println(...);
}

# ZXing (QR): pure Java, no reflection; CameraX ships its own consumer rules.
-dontwarn com.google.zxing.**
