package com.qrsg.app.ui.scanner

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.unit.dp
import com.qrsg.app.BuildConfig
import com.qrsg.app.data.reputation.SafeBrowsingV5Provider
import com.qrsg.app.data.reputation.AndroidAppIdentity
import com.qrsg.app.domain.analyzer.HeuristicRuleId
import com.qrsg.app.domain.analyzer.UrlAnalysisResult
import com.qrsg.app.domain.reputation.ReputationFailure
import com.qrsg.app.domain.reputation.ReputationResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/** Level 2 only: reputation results not overwrite local heuristic findings. */
@Composable
fun OnlineReputationSection(
    url: String,
    localResult: UrlAnalysisResult,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val provider = remember(context) {
        SafeBrowsingV5Provider(BuildConfig.QRSG_SAFE_BROWSING_API_KEY, AndroidAppIdentity.from(context))
    }
    val scope = rememberCoroutineScope()
    val uriHandler = LocalUriHandler.current
    var consent by remember(url) { mutableStateOf(false) }
    var loading by remember(url) { mutableStateOf(false) }
    var lookupResult by remember(url) { mutableStateOf<ReputationResult?>(null) }

    val blockedReason = when {
        !localResult.isWebUrl -> "Online check is not available for this QR content."
        localResult.findings.any { it.id == HeuristicRuleId.NON_PUBLIC_DESTINATION } ->
            "Local/private destinations are not sent to reputation services."
        localResult.findings.any { it.id == HeuristicRuleId.USER_INFO } ->
            "This URL contains user information before @. It will not be uploaded."
        localResult.findings.any { it.id in setOf(HeuristicRuleId.NUMERIC_HOST, HeuristicRuleId.LEADING_ZERO_IPV4) } ->
            "Ambiguous numerical host. This URL will not be uploaded."
        else -> null
    }

    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Level 2 · Online reputation", style = MaterialTheme.typography.titleMedium)
        if (blockedReason != null) {
            Text(blockedReason, style = MaterialTheme.typography.bodySmall)
            return@Column
        }
        Text(
            "Optional: sends the FULL URL (path and query included) to Google Safe Browsing. " +
                "URLs may contain private tokens and Google may share submitted URLs. Detection is not perfect.",
            style = MaterialTheme.typography.bodySmall,
        )
        Row {
            Checkbox(checked = consent, onCheckedChange = { consent = it })
            Text(
                "I understand and agree to share this URL for a reputation check.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Button(
            enabled = consent && !loading,
            onClick = {
                loading = true
                scope.launch {
                    try {
                        lookupResult = provider.checkUrl(url)
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } finally {
                        loading = false
                    }
                }
            },
        ) { Text(if (loading) "Checking…" else "Check Google Safe Browsing") }
        when (val r = lookupResult) {
            null -> Unit
            is ReputationResult.KnownThreat -> {
                Text(
                    "Potential threat reported by Google: ${r.threatTypes.joinToString()}. " +
                        "Detection is not certain; false positives are possible.",
                    color = MaterialTheme.colorScheme.error,
                )
                Text("Advisory provided by Google. Re-check if this result is older than 30 minutes.",
                    style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = { uriHandler.openUri("https://safebrowsing.google.com/") }) {
                    Text("Google Safe Browsing information")
                }
            }
            is ReputationResult.NoKnownThreat -> Text(
                "No known threat found in Google's lists. This does NOT mean the URL is safe.",
                style = MaterialTheme.typography.bodyMedium,
            )
            is ReputationResult.Unavailable -> Text(
                when (r.reason) {
                    ReputationFailure.NOT_CONFIGURED -> "Google Safe Browsing API key is not configured."
                    ReputationFailure.RATE_LIMITED -> "API rate limit exceeded. Reputation unknown."
                    ReputationFailure.AUTHENTICATION -> "API key rejected. Reputation unknown."
                    ReputationFailure.NETWORK -> "Network unavailable or request timed out. Reputation unknown."
                    ReputationFailure.PROVIDER_ERROR -> "Google Safe Browsing is temporarily unavailable."
                    ReputationFailure.MALFORMED_RESPONSE -> "Unexpected API response. Reputation unknown."
                },
                style = MaterialTheme.typography.bodyMedium,
            )
            is ReputationResult.Skipped -> Text("Online check skipped: ${r.reason}.")
        }
    }
}
