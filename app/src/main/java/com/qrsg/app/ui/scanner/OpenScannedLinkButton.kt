package com.qrsg.app.ui.scanner

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.qrsg.app.domain.link.ReviewedWebLinkParser
import com.qrsg.app.domain.risk.OverallRisk
import com.qrsg.app.domain.risk.RiskAssessment

/** The only place in QRSG that launches the scanned URL. User initiated, never automatic. */
@Composable
fun OpenScannedLinkButton(
    rawValue: String,
    assessment: RiskAssessment,
    onlineCheckInProgress: Boolean,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val link = remember(rawValue) { ReviewedWebLinkParser.parse(rawValue) }
    var confirmationVisible by remember(rawValue) { mutableStateOf(false) }
    var errorText by remember(rawValue) { mutableStateOf<String?>(null) }

    if (link == null) return

    OutlinedButton(
        onClick = {
            errorText = null
            confirmationVisible = true
        },
        enabled = !onlineCheckInProgress,
        modifier = modifier.fillMaxWidth(),
    ) {
        Text(if (onlineCheckInProgress) "Waiting for reputation check…" else "Open link")
    }

    errorText?.let { error ->
        Text(error, color = MaterialTheme.colorScheme.error)
    }

    if (confirmationVisible) {
        val warning = when (assessment.risk) {
            OverallRisk.HIGH_RISK ->
                "Google Safe Browsing reported a known threat. This site may be malicious."
            OverallRisk.SUSPICIOUS ->
                "Local security checks found suspicious indicators in this URL."
            OverallRisk.UNVERIFIED ->
                "The link's reputation has not been verified."
            OverallRisk.LOW_RISK ->
                "No known indicators were found. That does not guarantee the site is safe."
        }
        AlertDialog(
            onDismissRequest = { confirmationVisible = false },
            title = {
                Text(if (assessment.risk == OverallRisk.HIGH_RISK) "Known threat — open anyway?"
                     else "Open external link?")
            },
            text = {
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                ) {
                    Text("Destination host: ${link.actualHost}")
                    if (link.hasUserInfo) {
                        Text(
                            "Warning: the URL contains user-info before @. " +
                                "The actual destination is the hostname shown above.",
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    Text(warning,
                        color = if (assessment.risk == OverallRisk.HIGH_RISK)
                            MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.onSurface,
                    )
                    Text("Scanned URL: ${link.originalUrl}", style = MaterialTheme.typography.bodySmall)
                    Text("QRSG will hand this URL to another app. " +
                        "That app may follow redirects, which QRSG has not inspected.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            },
            confirmButton = {
                TextButton(
                    enabled = !onlineCheckInProgress,
                    onClick = {
                        confirmationVisible = false
                        try {
                            val view = Intent(Intent.ACTION_VIEW, Uri.parse(link.originalUrl)).apply {
                                addCategory(Intent.CATEGORY_BROWSABLE)
                            }
                            context.startActivity(
                                Intent.createChooser(view, "Open with").apply {
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                }
                            )
                        } catch (_: ActivityNotFoundException) {
                            errorText = "No app is available to open this URL."
                        } catch (_: SecurityException) {
                            errorText = "Android blocked opening this URL."
                        }
                    },
                ) {
                    Text(
                        if (assessment.risk == OverallRisk.LOW_RISK) "Open link" else "Open anyway",
                        color = if (assessment.risk == OverallRisk.HIGH_RISK)
                            MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.primary,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmationVisible = false }) { Text("Cancel") }
            },
        )
    }
}
