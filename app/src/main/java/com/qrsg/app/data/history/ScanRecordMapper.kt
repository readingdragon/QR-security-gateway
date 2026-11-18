package com.qrsg.app.data.history

import com.qrsg.app.domain.analyzer.UrlAnalysisResult
import com.qrsg.app.domain.reputation.ReputationResult
import com.qrsg.app.domain.risk.HybridRiskEngine

/** Deterministic, pure mapping: raw QR content never enters the database. */
object ScanRecordMapper {
    fun fromAssessment(
        id: String,
        scannedAtMs: Long,
        local: UrlAnalysisResult,
        online: ReputationResult?,
    ): ScanRecord {
        val status = when (online) {
            null -> "NOT_CHECKED"
            is ReputationResult.KnownThreat -> "KNOWN_THREAT"
            is ReputationResult.NoKnownThreat -> "NO_KNOWN_THREAT"
            is ReputationResult.Unavailable -> "UNAVAILABLE_${online.reason.name}"
            is ReputationResult.Skipped -> "SKIPPED_${online.reason.name}"
        }
        val threats = (online as? ReputationResult.KnownThreat)
            ?.threatTypes.orEmpty()
            .filter { it.matches(Regex("[A-Z0-9_]{1,64}")) }
            .sorted().joinToString("|")
        return ScanRecord(
            id = id,
            scannedAtMs = scannedAtMs,
            localRisk = local.riskLevel.name,
            onlineStatus = status,
            finalRisk = HybridRiskEngine.assess(local, online).risk.name,
            findingIds = local.findings.map { it.id.name }.distinct().sorted().joinToString("|"),
            threatTypes = threats,
        )
    }
}
