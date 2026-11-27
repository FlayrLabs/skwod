package io.skwod.app

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.abs

// Brand palette — deep-space background, MONOCHROME white accent (matches the iOS "Liquid Glass"
// look: the frosted material carries the depth, not a brand color). `SkAccent` is the app-wide
// accent; `SkAccentWash` a softer neutral for secondary accents.
private val Bg = Color(0xFF0E0F16)
private val SurfaceGlass = Color(0xFF161927)
val SkAccent = Color.White
val SkAccentWash = Color(0.72f, 0.72f, 0.72f)

// Frosted-glass surface tones (translucent — the backdrop's glow shows through, like iOS material).
/** Cards / rows floating on the backdrop. */
val GlassCardTone = Color(0xB31A1E2E)
/** Dialogs / popups — denser so text stays crisp, still lets the glow bleed through. */
val GlassDialogTone = Color(0xF0141726)

private val SkwodColors = darkColorScheme(
    primary = SkAccent,
    onPrimary = Color.Black,
    background = Bg,
    surface = SurfaceGlass,
    onSurface = Color.White,
    onBackground = Color.White,
    secondary = SkAccentWash,
    // AlertDialogs, menus, and sheets draw from the container roles — glass tones so every popup
    // reads as frosted glass over the backdrop instead of an opaque Material panel.
    surfaceContainer = GlassDialogTone,
    surfaceContainerHigh = GlassDialogTone,
    surfaceContainerHighest = GlassDialogTone,
    surfaceContainerLow = GlassCardTone,
)

@Composable
fun SkwodTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = SkwodColors, typography = Typography(), content = content)
}

/**
 * The app-wide frosted-glass backdrop, mirroring iOS `SkwodBackground`: a deep base with indigo /
 * violet radial glows under a soft white sheen. Every screen renders over this, and surfaces above
 * it use translucent washes — the Android take on the Liquid Glass look (no real blur-behind on
 * this API level, so the glass is simulated with translucency over the glows).
 */
@Composable
fun SkwodBackground(modifier: Modifier = Modifier) {
    Box(
        modifier.fillMaxSize().background(Color(0xFF0E0F16))
            .background(
                Brush.radialGradient(
                    colors = listOf(Color(0x574D529E), Color.Transparent),
                    center = androidx.compose.ui.geometry.Offset(0f, 0f), radius = 1500f
                )
            )
            .background(
                Brush.radialGradient(
                    colors = listOf(Color(0x386B4294), Color.Transparent),
                    center = androidx.compose.ui.geometry.Offset(1100f, 2200f), radius = 1600f
                )
            )
            .background(
                Brush.verticalGradient(
                    colors = listOf(Color(0x0DFFFFFF), Color.Transparent, Color(0x47000000))
                )
            )
    )
}

/** Wraps screen content over the frosted backdrop — the standard screen container. */
@Composable
fun GlassScreen(content: @Composable BoxScope.() -> Unit) {
    Box(Modifier.fillMaxSize()) {
        SkwodBackground()
        content()
    }
}

/**
 * Deterministic MONOCHROME shade from a string (avatars, server tiles) — a neutral gray whose
 * lightness varies per name, so avatars stay distinguishable without any color. Mirrors iOS
 * `Color.seeded` (djb2 hash → white 0.34–0.75).
 */
fun seededColor(seed: String): Color {
    var h = 5381
    for (b in seed.toByteArray()) h = (h shl 5) + h + b.toInt()
    val shade = 0.34f + ((h % 42 + 42) % 42) / 100f
    return Color(shade, shade, shade)
}

/** A soft rounded "glass" card on the deep background. */
@Composable
fun GlassCard(content: @Composable ColumnScope.() -> Unit) {
    Surface(
        color = GlassCardTone,
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(16.dp), content = content)
    }
}

/** Title used in screen headers. */
@Composable
fun ScreenTitle(text: String, subtitle: String? = null) {
    Column {
        Text(text, color = Color.White, fontSize = 28.sp, fontWeight = FontWeight.Bold)
        if (subtitle != null) Text(subtitle, color = Color.White.copy(alpha = 0.55f), fontSize = 14.sp)
    }
}

/**
 * The app's (adaptive) squid icon rasterized to an ImageBitmap — the brand logo, used as the home
 * rail tile and the auth header, matching iOS's `SkwodLogoTile` (the one splash of color).
 */
@Composable
fun rememberAppLogo(): androidx.compose.ui.graphics.ImageBitmap {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    return androidx.compose.runtime.remember {
        val d = ctx.packageManager.getApplicationIcon(ctx.packageName)
        val bmp = android.graphics.Bitmap.createBitmap(144, 144, android.graphics.Bitmap.Config.ARGB_8888)
        d.setBounds(0, 0, 144, 144); d.draw(android.graphics.Canvas(bmp))
        bmp.asImageBitmap()
    }
}

/** Presence palette + labels shared by the you-bar and status menus (mirrors iOS PresenceStyle).
 *  Green = available, yellow = away, red = Do Not Disturb only; grey = offline, or not known now
 *  (the dot is always shown). */
fun presenceColor(status: String): Color = when (status) {
    "online" -> Color(0xFF4ADE80)
    "idle" -> Color(0xFFFACC15)
    "dnd" -> Color(0xFFF87171)
    else -> Color(0xFF8E8E93)
}

fun presenceLabel(status: String): String = when (status) {
    "online" -> "Online"
    "idle" -> "Idle"
    "dnd" -> "Do Not Disturb"
    else -> "Invisible"   // "offline" from your own perspective reads as Invisible (matches iOS)
}

/** A circular monogram avatar. */
@Composable
fun Monogram(name: String, size: Int = 46) {
    Box(
        Modifier.size(size.dp).clip(RoundedCornerShape(50)).background(seededColor(name)),
        contentAlignment = Alignment.Center
    ) {
        Text(name.firstOrNull()?.uppercaseChar()?.toString() ?: "?", color = Color.White, fontWeight = FontWeight.Bold)
    }
}

/** A circular avatar: the E2EE image if we hold one for `key`, else the seeded monogram fallback.
 *  Drop-in replacement for Monogram at profile/member/DM sites. */
@Composable
fun AvatarImage(key: String?, name: String, size: Int = 46) {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val model = remember { AppModel.get(ctx) }
    val map by model.avatars.images   // read the state so we recompose when it changes
    val bmp = key?.let { if (map.containsKey(it)) model.avatars.bitmap(it) else null }
    if (bmp != null) {
        androidx.compose.foundation.Image(
            bmp.asImageBitmap(), name,
            Modifier.size(size.dp).clip(RoundedCornerShape(50)),
            contentScale = androidx.compose.ui.layout.ContentScale.Crop
        )
    } else Monogram(name, size)
}

/** A rounded-square avatar for server/skwod rail tiles. */
@Composable
fun AvatarTile(key: String?, name: String, size: Int = 48, corner: Int = 16) {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val model = remember { AppModel.get(ctx) }
    val map by model.avatars.images
    val bmp = key?.let { if (map.containsKey(it)) model.avatars.bitmap(it) else null }
    Box(Modifier.size(size.dp).clip(RoundedCornerShape(corner.dp)), contentAlignment = Alignment.Center) {
        if (bmp != null) {
            androidx.compose.foundation.Image(
                bmp.asImageBitmap(), name, Modifier.size(size.dp),
                contentScale = androidx.compose.ui.layout.ContentScale.Crop
            )
        } else {
            Box(Modifier.size(size.dp).background(seededColor(name)), contentAlignment = Alignment.Center) {
                Text(name.firstOrNull()?.uppercaseChar()?.toString() ?: "?", color = Color.White, fontWeight = FontWeight.Bold)
            }
        }
    }
}
