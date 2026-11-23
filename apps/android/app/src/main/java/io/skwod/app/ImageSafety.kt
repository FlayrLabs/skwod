package io.skwod.app

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * Every image this app decodes or sends goes through here — the Android peer of Apple's
 * `SafeImage`.
 *
 * **Inbound** (avatars, thumbnails, feed photos, full-size attachments — all chosen by someone
 * else): the header is read first (`inJustDecodeBounds`) and anything implausibly large is
 * refused before a single pixel is allocated, then the image is decoded subsampled to a bounded
 * size. A 30 kB file that claims 60 000 × 60 000 would otherwise throw OutOfMemoryError the
 * moment a row draws it — and because the message stays in history, on every launch.
 *
 * **Outbound** (photos the user attaches or posts): the picture is re-encoded from its pixels
 * alone, so nothing the camera wrote beside them — GPS position, device model, capture time,
 * embedded previews — leaves the device, encrypted or not.
 */
object SafeImage {
    /** Encoded bytes above this are not looked at as an image at all. */
    const val MAX_ENCODED_BYTES = 64 * 1024 * 1024
    /** Pixel count above this is refused from the header (≈ 64 MP; a 48 MP phone photo passes). */
    const val MAX_PIXELS = 64_000_000L
    /** Longest edge any inbound image is decoded to for display. */
    const val DISPLAY_EDGE = 2048
    /** Longest edge of a photo we send. */
    const val OUTBOUND_EDGE = 4096

    /** Whether `width × height` is a size this app is willing to decode. Pure. */
    fun plausible(width: Int, height: Int): Boolean =
        width in 1..65_535 && height in 1..65_535 && width.toLong() * height.toLong() <= MAX_PIXELS

    /** The power-of-two subsample that brings the long edge to at most ~`maxEdge`. Pure. */
    fun sampleSize(width: Int, height: Int, maxEdge: Int): Int {
        var sample = 1
        val long = maxOf(width, height)
        while (long / sample > maxEdge) sample *= 2
        return sample
    }

    private fun bounds(data: ByteArray): BitmapFactory.Options? {
        if (data.isEmpty() || data.size > MAX_ENCODED_BYTES) return null
        val o = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(data, 0, data.size, o)
        return if (plausible(o.outWidth, o.outHeight)) o else null
    }

    // ---- inbound: pictures someone else chose, decoded without the user asking ----

    /** Pixel count above this is not decoded for display (a 6000 × 6000 picture passes; this app sends at most 4096 px). */
    const val MAX_INBOUND_PIXELS = 36_000_000L

    /** The formats this app itself sends or has sent. Nothing else is handed to the decoder for someone else's bytes. */
    fun inboundFormat(format: Format): Boolean = format != Format.OTHER

    fun plausibleInbound(width: Int, height: Int): Boolean = plausible(width, height) && width.toLong() * height.toLong() <= MAX_INBOUND_PIXELS

    /**
     * [decode] for bytes that came from someone else (avatars, thumbnails, feed photos): only
     * the known formats, by the bytes' own header, and a tighter size. Null otherwise.
     */
    fun decodeInbound(data: ByteArray, maxEdge: Int = DISPLAY_EDGE): Bitmap? = try {
        val b = if (inboundFormat(sniff(data))) bounds(data) else null
        if (b == null || !plausibleInbound(b.outWidth, b.outHeight)) null else decode(data, maxEdge)
    } catch (_: Throwable) { null }

    /** The same for a decrypted attachment on disk. */
    fun decodeInboundFile(file: File, maxEdge: Int = DISPLAY_EDGE): Bitmap? = try {
        val head = ByteArray(32)
        val n = file.inputStream().use { it.read(head) }
        val b = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        if (n <= 0 || !inboundFormat(sniff(head.copyOf(n)))) null else {
            BitmapFactory.decodeFile(file.absolutePath, b)
            if (!plausibleInbound(b.outWidth, b.outHeight)) null else decodeFile(file, maxEdge)
        }
    } catch (_: Throwable) { null }

    /** Pixel size from the header only, or null if it is not an acceptable image. */
    fun size(data: ByteArray): Pair<Int, Int>? = bounds(data)?.let { it.outWidth to it.outHeight }

    /** Decode `data` to at most `maxEdge` px on its long edge, or null (never throws, never OOMs
     *  on a hostile header). */
    fun decode(data: ByteArray, maxEdge: Int = DISPLAY_EDGE): Bitmap? = try {
        val b = bounds(data)
        if (b == null) null else {
            val o = BitmapFactory.Options().apply { inSampleSize = sampleSize(b.outWidth, b.outHeight, maxEdge) }
            BitmapFactory.decodeByteArray(data, 0, data.size, o)?.let { fit(it, maxEdge) }
        }
    } catch (_: Throwable) { null }   // incl. OutOfMemoryError

    /** The same for a decrypted attachment on disk. */
    fun decodeFile(file: File, maxEdge: Int = DISPLAY_EDGE): Bitmap? = try {
        if (file.length() <= 0 || file.length() > MAX_ENCODED_BYTES) null else {
            val b = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeFile(file.absolutePath, b)
            if (!plausible(b.outWidth, b.outHeight)) null else {
                val o = BitmapFactory.Options().apply { inSampleSize = sampleSize(b.outWidth, b.outHeight, maxEdge) }
                BitmapFactory.decodeFile(file.absolutePath, o)?.let { fit(it, maxEdge) }
            }
        }
    } catch (_: Throwable) { null }

    /** inSampleSize only halves; finish the job so the long edge really is ≤ maxEdge. */
    private fun fit(bmp: Bitmap, maxEdge: Int): Bitmap {
        val long = maxOf(bmp.width, bmp.height)
        if (long <= maxEdge) return bmp
        val scale = maxEdge.toFloat() / long
        return Bitmap.createScaledBitmap(bmp, maxOf(1, (bmp.width * scale).toInt()), maxOf(1, (bmp.height * scale).toInt()), true)
    }

    // ---- outbound ----

    /** What kind of image the bytes are, from their own header (not a name or a claimed type). */
    enum class Format { JPEG, PNG, GIF, WEBP, ANIMATED_WEBP, HEIF, OTHER }

    /** Pure header sniff. */
    fun sniff(d: ByteArray): Format {
        fun at(i: Int, s: String) = d.size >= i + s.length && s.indices.all { d[i + it] == s[it].code.toByte() }
        return when {
            d.size >= 3 && d[0] == 0xFF.toByte() && d[1] == 0xD8.toByte() && d[2] == 0xFF.toByte() -> Format.JPEG
            d.size >= 8 && d[0] == 0x89.toByte() && at(1, "PNG") -> Format.PNG
            at(0, "GIF87a") || at(0, "GIF89a") -> Format.GIF
            at(0, "RIFF") && at(8, "WEBP") ->
                // VP8X with the animation flag (bit 1 of the flags byte at offset 20).
                if (at(12, "VP8X") && d.size > 20 && (d[20].toInt() and 0x02) != 0) Format.ANIMATED_WEBP else Format.WEBP
            at(4, "ftyp") && (at(8, "heic") || at(8, "heix") || at(8, "hevc") || at(8, "mif1") || at(8, "msf1") || at(8, "heif") || at(8, "avif")) -> Format.HEIF
            else -> Format.OTHER
        }
    }

    class Stripped(val data: ByteArray, val mime: String, val extension: String)

    /**
     * A photo ready to send: re-encoded from pixels only (no EXIF, GPS, maker notes, XMP or
     * embedded preview), EXIF orientation baked in, at most `maxEdge` px. PNG stays PNG and an
     * image with transparency becomes PNG; everything else — JPEG, HEIC, WebP — becomes JPEG.
     *
     * Returns null when the data is not a still image this can re-encode. A GIF or animated
     * WebP is null too: re-encoding would freeze it; see [sendAsIs].
     */
    fun stripped(data: ByteArray, maxEdge: Int = OUTBOUND_EDGE, quality: Int = 85): Stripped? {
        val format = sniff(data)
        if (format == Format.GIF || format == Format.ANIMATED_WEBP) return null
        val bmp = decode(data, maxEdge) ?: return null
        val upright = applyOrientation(bmp, orientation(data))
        val png = format == Format.PNG || upright.hasAlpha() && format != Format.JPEG
        val out = ByteArrayOutputStream()
        // Bitmap.compress writes pixels only: no source metadata is carried over.
        val ok = if (png) upright.compress(Bitmap.CompressFormat.PNG, 100, out)
                 else upright.compress(Bitmap.CompressFormat.JPEG, quality, out)
        if (!ok) return null
        return if (png) Stripped(out.toByteArray(), "image/png", "png") else Stripped(out.toByteArray(), "image/jpeg", "jpg")
    }

    /** A small upright JPEG (thumbnail, feed photo) from any acceptable image — pixels only. */
    fun jpeg(data: ByteArray, maxEdge: Int, quality: Int): ByteArray? = try {
        decode(data, maxEdge)?.let { bmp ->
            val out = ByteArrayOutputStream()
            if (applyOrientation(bmp, orientation(data)).compress(Bitmap.CompressFormat.JPEG, quality, out)) out.toByteArray() else null
        }
    } catch (_: Throwable) { null }

    /** Animated images carry no camera metadata and would be frozen by a re-encode: sent as is. */
    fun sendAsIs(data: ByteArray): Boolean = sniff(data).let { it == Format.GIF || it == Format.ANIMATED_WEBP }

    private fun orientation(data: ByteArray): Int = try {
        ExifInterface(ByteArrayInputStream(data)).getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)
    } catch (_: Throwable) { ExifInterface.ORIENTATION_NORMAL }

    private fun applyOrientation(bmp: Bitmap, orientation: Int): Bitmap {
        val m = Matrix()
        when (orientation) {
            ExifInterface.ORIENTATION_ROTATE_90 -> m.postRotate(90f)
            ExifInterface.ORIENTATION_ROTATE_180 -> m.postRotate(180f)
            ExifInterface.ORIENTATION_ROTATE_270 -> m.postRotate(270f)
            ExifInterface.ORIENTATION_FLIP_HORIZONTAL -> m.postScale(-1f, 1f)
            ExifInterface.ORIENTATION_FLIP_VERTICAL -> m.postScale(1f, -1f)
            ExifInterface.ORIENTATION_TRANSPOSE -> { m.postRotate(90f); m.postScale(-1f, 1f) }
            ExifInterface.ORIENTATION_TRANSVERSE -> { m.postRotate(270f); m.postScale(-1f, 1f) }
            else -> return bmp
        }
        return try { Bitmap.createBitmap(bmp, 0, 0, bmp.width, bmp.height, m, true) } catch (_: Throwable) { bmp }
    }

    /** Whether encoded image data still carries location or camera metadata (tests / self-check). */
    fun hasPrivateMetadata(data: ByteArray): Boolean = try {
        val exif = ExifInterface(ByteArrayInputStream(data))
        listOf(ExifInterface.TAG_GPS_LATITUDE, ExifInterface.TAG_GPS_LONGITUDE, ExifInterface.TAG_MAKE,
            ExifInterface.TAG_MODEL, ExifInterface.TAG_DATETIME_ORIGINAL).any { exif.getAttribute(it) != null }
    } catch (_: Throwable) { false }
}
