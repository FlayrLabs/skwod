package io.skwod.app

import java.io.File

/** Test vectors shared with the Apple logic tests (`apps/shared-test-vectors`). */
object SharedVectors {
    fun file(name: String): File {
        // Unit tests run in the module directory (apps/android/app); walk up to apps/.
        var dir: File? = File("").absoluteFile
        while (dir != null) {
            val f = File(dir, "shared-test-vectors/$name")
            if (f.isFile) return f
            dir = dir.parentFile
        }
        error("shared-test-vectors/$name not found above ${File("").absolutePath}")
    }

    fun load(name: String) = org.json.JSONObject(file(name).readText())
}
