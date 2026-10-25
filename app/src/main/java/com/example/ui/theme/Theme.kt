package com.example.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DTZDarkColorScheme = darkColorScheme(
    primary = NeonCyan,
    onPrimary = Color(0xFF001F29),
    primaryContainer = Color(0xFF004D61),
    onPrimaryContainer = Color(0xFFB8EAFF),
    secondary = NeonEmerald,
    onSecondary = Color(0xFF00220F),
    secondaryContainer = Color(0xFF005328),
    onSecondaryContainer = Color(0xFFA6F5C0),
    tertiary = NeonViolet,
    onTertiary = Color.White,
    background = CyberVoid,
    onBackground = TextPrimary,
    surface = CyberSurface,
    onSurface = TextPrimary,
    surfaceVariant = CyberSurfaceVariant,
    onSurfaceVariant = TextSecondary,
    outline = CyberCardBorder,
    error = NeonRed,
    onError = Color.White
)

@Composable
fun DTZShieldTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = DTZDarkColorScheme,
        typography = Typography,
        content = content
    )
}
