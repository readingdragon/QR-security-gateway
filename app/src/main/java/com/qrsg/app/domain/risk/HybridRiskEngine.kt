package com.qrsg.app.domain.risk

import com.qrsg.app.domain.analyzer.RiskLevel
import com.qrsg.app.domain.analyzer.UrlAnalysisResult
import com.qrsg.app.domain.reputation.ReputationResult

enum class OverallRisk {
    HIGH_RISK, SUSPICIOUS, LOW_RISK, UNVERIFIED
}

enum class EvidenceSource {
    LOCAL, GOOGLE_SAFE_BROWSING, STATUS
}

data class RiskEvidence(
    val source: EvidenceSource,
    val message: String,
)

data class RiskAssessment(
    val risk: OverallRisk,
    val title: String,
    val recommendation: String,
    val evidence: List<RiskEvidence>,
)

object HybridRiskEngine {

    fun assess(
        local: UrlAnalysisResult,
        online: ReputationResult? = null,
    ): RiskAssessment {

        val risk = when {
            online is ReputationResult.KnownThreat ->
                OverallRisk.HIGH_RISK

            local.findings.isNotEmpty() ||
                local.riskLevel == RiskLevel.SUSPICIOUS ->
                OverallRisk.SUSPICIOUS

            !local.isWebUrl ||
                local.riskLevel == RiskLevel.UNVERIFIED ->
                OverallRisk.UNVERIFIED

            online is ReputationResult.NoKnownThreat ->
                OverallRisk.LOW_RISK

            else -> OverallRisk.UNVERIFIED
        }

        val localEvidence = when {
            local.findings.isNotEmpty() -> local.findings.map {
                RiskEvidence(EvidenceSource.LOCAL, it.description)
            }

            !local.isWebUrl -> local.reasons.map {
                RiskEvidence(EvidenceSource.LOCAL, it)
            }

            local.riskLevel == RiskLevel.SUSPICIOUS ->
                local.reasons.ifEmpty {
                    listOf("The local analyzer flagged this URL.")
                }.map {
                    RiskEvidence(EvidenceSource.LOCAL, it)
                }

            else -> listOf(
                RiskEvidence(
                    EvidenceSource.LOCAL,
                    "No obvious local warning indicators were detected."
                )
            )
        }

        val onlineEvidence = when (online) {
            null -> RiskEvidence(
                EvidenceSource.STATUS,
                "Online reputation has not been checked."
            )

            is ReputationResult.KnownThreat -> {
                val types = online.threatTypes.sorted()
                    .joinToString()
                    .ifEmpty { "type unspecified" }

                RiskEvidence(
                    EvidenceSource.GOOGLE_SAFE_BROWSING,
                    "Google Safe Browsing reported a known threat: $types."
                )
            }

            is ReputationResult.NoKnownThreat -> RiskEvidence(
                EvidenceSource.GOOGLE_SAFE_BROWSING,
                "No match in Google's known-threat lists; this does not guarantee safety."
            )

            is ReputationResult.Unavailable -> RiskEvidence(
                EvidenceSource.STATUS,
                "Online reputation unavailable (${online.reason.name})."
            )

            is ReputationResult.Skipped -> RiskEvidence(
                EvidenceSource.STATUS,
                "Online lookup skipped (${online.reason.name})."
            )
        }

        val (title, recommendation) = when (risk) {
            OverallRisk.HIGH_RISK ->
                "Known threat reported" to
                    "Do not open this link. A threat-list match was reported."

            OverallRisk.SUSPICIOUS ->
                "Suspicious URL" to
                    "Review the destination carefully. A clean reputation lookup does not cancel local warnings."

            OverallRisk.LOW_RISK ->
                "No known indicators detected" to
                    "No obvious local warnings or known-list matches were found. This is not a guarantee of safety."

            OverallRisk.UNVERIFIED ->
                "Risk not verified" to
                    "The available checks cannot establish the URL's reputation. Avoid entering sensitive information without verification."
        }

        return RiskAssessment(
            risk,
            title,
            recommendation,
            localEvidence + onlineEvidence
        )
    }
}
