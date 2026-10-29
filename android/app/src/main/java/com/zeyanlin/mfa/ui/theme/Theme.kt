package com.zeyanlin.mfa.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

/**
 * Material 3, following the system wallpaper where the platform offers it.
 *
 * The fallback palette is a plain blue rather than a brand colour: there is no
 * brand yet, and inventing one here would only have to be undone.
 */
private val fallbackLight = lightColorScheme(
    primary = Color(0xFF17497D),
    secondary = Color(0xFF50606F),
)

private val fallbackDark = darkColorScheme(
    primary = Color(0xFFA6C8FF),
    secondary = Color(0xFFB7C8D9),
)

@Composable
fun MfaTheme(
    isDark: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val colors = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (isDark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        isDark -> fallbackDark
        else -> fallbackLight
    }

    MaterialTheme(colorScheme = colors, content = content)
}
