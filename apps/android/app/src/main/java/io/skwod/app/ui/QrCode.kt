package io.skwod.app

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * QR codes, entirely on-device: ZXing's pure-Java encoder/decoder and CameraX frames. No Google
 * Play Services, no ML Kit model download, no network — the scanner works in airplane mode.
 */
object Qr {
    /** Longest payload we will hand back from a scan (an invite is ~80 chars, ~300 with a fallback). */
    const val MAX_PAYLOAD = 1024
    /** Prefix of the QR a NEW device shows so an existing device can approve it. */
    const val LINK_PREFIX = "skwod-link:"

    /** Render `text` as a QR bitmap (black on white, quiet zone included). */
    fun bitmap(text: String, size: Int = 640): Bitmap? = try {
        val hints = mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 2)
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
        val pixels = IntArray(size * size) { i -> if (matrix.get(i % size, i / size)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt() }
        Bitmap.createBitmap(pixels, size, size, Bitmap.Config.ARGB_8888)
    } catch (_: Exception) { null }

    /** Decode one camera frame's luminance plane; null when there is no QR code in it. */
    fun decode(y: ByteArray, width: Int, height: Int): String? {
        val reader = MultiFormatReader().apply {
            setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE), DecodeHintType.TRY_HARDER to true))
        }
        return try {
            val source = PlanarYUVLuminanceSource(y, width, height, 0, 0, width, height, false)
            reader.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text?.takeIf { it.length <= MAX_PAYLOAD }
        } catch (_: Exception) { null } finally { reader.reset() }
    }

    /** The device-link code inside a scanned `skwod-link:<code>` payload (or a bare typed code). */
    fun linkCode(scanned: String): String? {
        val t = scanned.trim()
        val code = if (t.startsWith(LINK_PREFIX, ignoreCase = true)) t.substring(LINK_PREFIX.length) else t
        // 80 bits as 16 base32 characters, shown in groups: letters, digits and dashes only.
        if (code.length !in 16..40 || !code.all { it.isLetterOrDigit() || it == '-' }) return null
        return code
    }
}

/** A QR code on a white tile (codes must stay dark-on-light to scan). */
@Composable
fun QrImage(text: String, modifier: Modifier = Modifier, sizeDp: Int = 200) {
    val bmp = remember(text) { Qr.bitmap(text) }
    if (bmp != null) {
        Image(bmp.asImageBitmap(), "QR code",
            modifier.size(sizeDp.dp).clip(RoundedCornerShape(12.dp)).background(Color.White))
    }
}

/**
 * Full-screen camera scanner. Calls [onResult] once with the raw text of the first QR code seen;
 * the caller validates it (an invite goes through [InviteLink.parse], a link code through
 * [Qr.linkCode]) — a scanned code is untrusted input like any pasted text.
 */
@Composable
fun QrScannerDialog(title: String, hint: String, onResult: (String) -> Unit, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    var denied by remember { mutableStateOf(false) }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        granted = ok; denied = !ok
    }
    LaunchedEffect(Unit) { if (!granted) ask.launch(Manifest.permission.CAMERA) }

    val executor = remember { Executors.newSingleThreadExecutor() }
    val done = remember { AtomicBoolean(false) }
    DisposableEffect(Unit) {
        onDispose {
            try { ProcessCameraProvider.getInstance(ctx).get().unbindAll() } catch (_: Exception) {}
            executor.shutdown()
        }
    }

    Dialog(onDismissRequest = onClose) {
        Surface(color = Color(0xFF14141C), shape = RoundedCornerShape(20.dp)) {
            Column(Modifier.padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Text(title, color = Color.White, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(10.dp))
                Box(Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(16.dp)).background(Color.Black),
                    contentAlignment = Alignment.Center) {
                    when {
                        granted -> AndroidView(modifier = Modifier.fillMaxSize(), factory = { viewCtx ->
                            val previewView = PreviewView(viewCtx)
                            val future = ProcessCameraProvider.getInstance(viewCtx)
                            future.addListener({
                                try {
                                    val provider = future.get()
                                    val preview = Preview.Builder().build().also { it.setSurfaceProvider(previewView.surfaceProvider) }
                                    val analysis = ImageAnalysis.Builder()
                                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build()
                                    analysis.setAnalyzer(executor) { frame: ImageProxy ->
                                        val text = if (done.get()) null else decodeFrame(frame)
                                        frame.close()
                                        if (text != null && done.compareAndSet(false, true)) {
                                            ContextCompat.getMainExecutor(viewCtx).execute { onResult(text) }
                                        }
                                    }
                                    provider.unbindAll()
                                    provider.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
                                } catch (_: Exception) {}
                            }, ContextCompat.getMainExecutor(viewCtx))
                            previewView
                        })
                        denied -> Text("Skwod needs the camera to scan a code. Allow it in Settings, or paste / type the code instead.",
                            color = Color.White.copy(alpha = 0.7f), textAlign = TextAlign.Center, modifier = Modifier.padding(20.dp))
                        else -> CircularProgressIndicator(color = Color.White)
                    }
                }
                Spacer(Modifier.height(10.dp))
                Text(hint, color = Color.White.copy(alpha = 0.6f), style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center)
                TextButton(onClick = onClose) { Text("Cancel") }
            }
        }
    }
}

/** Copy the frame's Y plane (honouring row stride) and look for a QR code in it. */
private fun decodeFrame(frame: ImageProxy): String? {
    val plane = frame.planes.firstOrNull() ?: return null
    val width = frame.width; val height = frame.height
    val buffer = plane.buffer
    val rowStride = plane.rowStride
    val y = ByteArray(width * height)
    return try {
        if (rowStride == width) {
            buffer.get(y, 0, minOf(y.size, buffer.remaining()))
        } else {
            for (row in 0 until height) {
                buffer.position(row * rowStride)
                buffer.get(y, row * width, minOf(width, buffer.remaining()))
            }
        }
        Qr.decode(y, width, height)
    } catch (_: Exception) { null }
}
