package com.firewall.dns.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val BrandBlue = Color(0xFF2457D6)
private val BrandBlueDark = Color(0xFFB7C7FF)
private val Ink = Color(0xFF17233A)
private val Slate = Color(0xFF5C687D)
private val Canvas = Color(0xFFF5F7FB)
private val DarkCanvas = Color(0xFF101722)
private val DarkSurface = Color(0xFF192331)
private val SecureGreen = Color(0xFF16845B)
private val SecureGreenDark = Color(0xFF72D7AD)

private val LightFirewallColors = lightColorScheme(
    primary = BrandBlue,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE5ECFF),
    onPrimaryContainer = Ink,
    secondary = SecureGreen,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFDDF5E9),
    onSecondaryContainer = Color(0xFF123D2D),
    background = Canvas,
    onBackground = Ink,
    surface = Color.White,
    onSurface = Ink,
    surfaceVariant = Color(0xFFE9EDF4),
    onSurfaceVariant = Slate,
    outline = Color(0xFFD5DCE7),
    error = Color(0xFFBA3444),
    errorContainer = Color(0xFFFFE9EC),
    onErrorContainer = Color(0xFF641B25)
)

private val DarkFirewallColors = darkColorScheme(
    primary = BrandBlueDark,
    onPrimary = Color(0xFF10275F),
    primaryContainer = Color(0xFF223A70),
    onPrimaryContainer = Color(0xFFE0E7FF),
    secondary = SecureGreenDark,
    onSecondary = Color(0xFF003824),
    secondaryContainer = Color(0xFF174B37),
    onSecondaryContainer = Color(0xFFC9F2DF),
    background = DarkCanvas,
    onBackground = Color(0xFFE4EAF4),
    surface = DarkSurface,
    onSurface = Color(0xFFE4EAF4),
    surfaceVariant = Color(0xFF263344),
    onSurfaceVariant = Color(0xFFB6C2D3),
    outline = Color(0xFF3B4A5E),
    error = Color(0xFFFFB4B8),
    errorContainer = Color(0xFF5A202A),
    onErrorContainer = Color(0xFFFFDADB)
)

private val FirewallTypography = Typography(
    headlineSmall = TextStyle(fontSize = 26.sp, lineHeight = 32.sp, fontWeight = FontWeight.ExtraBold, letterSpacing = (-0.3).sp),
    titleLarge = TextStyle(fontSize = 20.sp, lineHeight = 26.sp, fontWeight = FontWeight.Bold),
    titleMedium = TextStyle(fontSize = 16.sp, lineHeight = 22.sp, fontWeight = FontWeight.SemiBold),
    bodyMedium = TextStyle(fontSize = 14.sp, lineHeight = 21.sp),
    bodySmall = TextStyle(fontSize = 12.sp, lineHeight = 18.sp),
    labelMedium = TextStyle(fontSize = 12.sp, lineHeight = 16.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.3.sp)
)

private val FirewallShapes = Shapes(
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(18.dp),
    large = RoundedCornerShape(26.dp)
)

@Composable
fun FirewallTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (androidx.compose.foundation.isSystemInDarkTheme()) {
            DarkFirewallColors
        } else {
            LightFirewallColors
        },
        typography = FirewallTypography,
        shapes = FirewallShapes,
        content = content
    )
}
