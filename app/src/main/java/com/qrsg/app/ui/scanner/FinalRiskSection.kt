package com.qrsg.app.ui.scanner

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.qrsg.app.domain.risk.EvidenceSource
import com.qrsg.app.domain.risk.OverallRisk
import com.qrsg.app.domain.risk.RiskAssessment

@Composable
fun FinalRiskSection(
    assessment: RiskAssessment,
    modifier: Modifier = Modifier
) {
    val color = when (assessment.risk) {
        OverallRisk.HIGH_RISK,
        OverallRisk.SUSPICIOUS -> MaterialTheme.colorScheme.error

        OverallRisk.LOW_RISK -> MaterialTheme.colorScheme.primary

        OverallRisk.UNVERIFIED -> MaterialTheme.colorScheme.tertiary
    }

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Text(
            "Level 3 · Final risk assessment",
            style = MaterialTheme.typography.titleMedium
        )

        Text(
            assessment.title,
            color = color,
            style = MaterialTheme.typography.titleLarge
        )

        Text(
            assessment.recommendation,
            style = MaterialTheme.typography.bodyMedium
        )

        assessment.evidence.forEach { evidence ->
            val source = when (evidence.source) {
                EvidenceSource.LOCAL -> "Local"
                EvidenceSource.GOOGLE_SAFE_BROWSING -> "Google"
                EvidenceSource.STATUS -> "Status"
            }

            Text(
                "• $source: ${evidence.message}",
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}