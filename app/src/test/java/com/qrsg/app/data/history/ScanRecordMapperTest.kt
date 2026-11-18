package com.qrsg.app.data.history

import com.qrsg.app.domain.analyzer.FindingSeverity
import com.qrsg.app.domain.analyzer.HeuristicFinding
import com.qrsg.app.domain.analyzer.HeuristicRuleId
import com.qrsg.app.domain.analyzer.RiskLevel
import com.qrsg.app.domain.analyzer.UrlAnalysisResult
import com.qrsg.app.domain.reputation.ReputationResult
import org.junit.Assert.*
import org.junit.Test

class ScanRecordMapperTest {
    private val clean = UrlAnalysisResult(
        RiskLevel.LOW_RISK, "Local check", listOf("No local warnings"), true
    )

    @Test fun offlineRemainsUnverified() {
        val r = ScanRecordMapper.fromAssessment("id-1", 0L, clean, null)
        assertEquals("NOT_CHECKED", r.onlineStatus)
        assertEquals("UNVERIFIED", r.finalRisk)
    }

    @Test fun cleanAndOnlineNoMatchMeansLowRisk() {
        val r = ScanRecordMapper.fromAssessment("id-2", 0L, clean,
            ReputationResult.NoKnownThreat(0L))
        assertEquals("LOW_RISK", r.finalRisk)
        assertEquals("NO_KNOWN_THREAT", r.onlineStatus)
    }

    @Test fun localWarningsCannotBeOverriddenByCleanReputation() {
        val suspicious = clean.copy(
            riskLevel = RiskLevel.SUSPICIOUS,
            findings = listOf(HeuristicFinding(
                HeuristicRuleId.SHORTENER, FindingSeverity.MEDIUM, "Short link"
            ))
        )
        val r = ScanRecordMapper.fromAssessment("id-3", 0L, suspicious,
            ReputationResult.NoKnownThreat(0L))
        assertEquals("SUSPICIOUS", r.finalRisk)
        assertEquals("SHORTENER", r.findingIds)
    }

    @Test fun knownThreatHasPriority() {
        val r = ScanRecordMapper.fromAssessment("id-4", 0L, clean,
            ReputationResult.KnownThreat(setOf("SOCIAL_ENGINEERING"), 0L))
        assertEquals("HIGH_RISK", r.finalRisk)
        assertEquals("KNOWN_THREAT", r.onlineStatus)
        assertEquals("SOCIAL_ENGINEERING", r.threatTypes)
    }

    @Test fun maliciousThreatLabelsAreNotStored() {
        val r = ScanRecordMapper.fromAssessment("id-5", 0L, clean,
            ReputationResult.KnownThreat(setOf("MALWARE", "=HYPERLINK(\"https://evil\")"), 0L))
        assertEquals("MALWARE", r.threatTypes)
    }

    @Test fun noRawUrlOrQrValueStored() {
        val local = clean.copy(
            title = "https://host.test/private?token=secret",
            reasons = listOf("WIFI:T:WPA;P=secret;;")
        )
        val csv = HistoryCsv.encode(listOf(ScanRecordMapper.fromAssessment("id-6", 0L, local, null)))
        assertFalse(csv.contains("secret"))
        assertFalse(csv.contains("https://"))
        assertFalse(csv.contains("WIFI:"))
    }
}
