package com.qrsg.app.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

// private val DarkColorScheme = 
//   darkColorScheme(
//     primary = Purple80,
//     secondary = DarkGreen,
//     tertiary = Pink80
//     )

// private val LightColorScheme =
//   lightColorScheme(
//     primary = Purple40,
//     secondary = DarkGreen,
//     tertiary = Pink40,

//     // Other default colors to override
//     // background = DarkGreen,
//     // surface = Color(0xFFFFFBFE),
//     // onPrimary = Color.White,
//     // onSecondary = Color.White,
//     // onTertiary = Color.White,
//     // onBackground = Color(0xFF1C1B1F),
//     // onSurface = Color(0xFF1C1B1F),
    
//   )

private val LightColorScheme = lightColorScheme(
    primary = md_theme_light_primary,
    onPrimary = md_theme_light_onPrimary,
    primaryContainer = md_theme_light_primaryContainer,
    // ..
)
private val DarkColorScheme = darkColorScheme(
    primary = md_theme_dark_primary,
    onPrimary = md_theme_dark_onPrimary,
    primaryContainer = md_theme_dark_primaryContainer,
    // ..
)

@Composable
fun QRSGTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    // Dynamic color is available on Android 12+
    // dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme =
        if (!darkTheme) {
            LightColorScheme
        } else {
            DarkColorScheme
        }
    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )

// @Composable
// fun QRSGTheme(
//   darkTheme: Boolean = isSystemInDarkTheme(),
//   // Dynamic color is available on Android 12+
//   dynamicColor: Boolean = true,
//   content: @Composable () -> Unit,
// ) {
//   val colorScheme =
//     when {
//       dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
//         val context = LocalContext.current
//         if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
//       }
//       darkTheme -> DarkColorScheme
//       else -> LightColorScheme
//     }

//   MaterialTheme(colorScheme = colorScheme, typography = Typography, content = content)
}
