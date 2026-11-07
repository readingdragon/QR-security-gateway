package com.qrsg.app.ui.main

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.navigation3.runtime.NavKey
import com.qrsg.app.Scanner
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/** Replaces stale template assertions ("Hello Sample1!") from the existing repository. */
class MainScreenTest {
    @get:Rule val composeRule = createAndroidComposeRule<ComponentActivity>()
    private var lastNavigation: NavKey? = null

    @Before fun setup() {
        lastNavigation = null
        composeRule.setContent {
            MainScreen(onItemClick = { lastNavigation = it })
        }
    }

    @Test fun homeScreenShowsMainActions() {
        composeRule.onNodeWithText("QR_SG").assertExists()
        composeRule.onNodeWithText("Scan QR code").assertExists()
        composeRule.onNodeWithText("Scan history").assertExists()
    }

    @Test fun scanButtonNavigatesToScanner() {
        composeRule.onNodeWithText("Scan QR code").performClick()
        composeRule.runOnIdle { assertEquals(Scanner, lastNavigation) }
    }
}
