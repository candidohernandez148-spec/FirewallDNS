package com.firewall.dns.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
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
private val AmberWarn = Color(0xFFD97706)
private val AmberWarnDark = Color(0xFFFBBF24)

private val LightFirewallColors = lightColorScheme(
    primary = BrandBlue,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE5ECFF),
    onPrimaryContainer = Ink,
    secondary = SecureGreen,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFDDF5E9),
    onSecondaryContainer = Color(0xFF123D2D),
    tertiary = AmberWarn,
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
    tertiary = AmberWarnDark,
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
    headlineLarge = TextStyle(fontSize = 24.sp, lineHeight = 29.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.35).sp),
    headlineMedium = TextStyle(fontSize = 22.sp, lineHeight = 27.sp, fontWeight = FontWeight.Bold),
    headlineSmall = TextStyle(fontSize = 20.sp, lineHeight = 25.sp, fontWeight = FontWeight.Bold),
    titleLarge = TextStyle(fontSize = 18.sp, lineHeight = 23.sp, fontWeight = FontWeight.Bold),
    titleMedium = TextStyle(fontSize = 15.sp, lineHeight = 20.sp, fontWeight = FontWeight.SemiBold),
    titleSmall = TextStyle(fontSize = 13.sp, lineHeight = 18.sp, fontWeight = FontWeight.SemiBold),
    bodyLarge = TextStyle(fontSize = 14.sp, lineHeight = 19.sp),
    bodyMedium = TextStyle(fontSize = 13.sp, lineHeight = 18.sp),
    bodySmall = TextStyle(fontSize = 11.sp, lineHeight = 15.sp),
    labelLarge = TextStyle(fontSize = 12.sp, lineHeight = 16.sp, fontWeight = FontWeight.SemiBold),
    labelMedium = TextStyle(fontSize = 11.sp, lineHeight = 14.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.2.sp),
    labelSmall = TextStyle(fontSize = 10.sp, lineHeight = 13.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.15.sp)
)

private val FirewallShapes = Shapes(
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(20.dp)
)

@Composable
fun FirewallTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkFirewallColors else LightFirewallColors,
        typography = FirewallTypography,
        shapes = FirewallShapes,
        content = content
    )
}
