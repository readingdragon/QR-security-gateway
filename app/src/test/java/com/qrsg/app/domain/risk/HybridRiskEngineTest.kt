package com.qrsg.app.domain.risk

import com.qrsg.app.domain.analyzer.*
import com.qrsg.app.domain.reputation.*
import org.junit.Assert.assertEquals
import org.junit.Test

class HybridRiskEngineTest {

    private val clean = UrlAnalysisResult(
        riskLevel = RiskLevel.LOW_RISK,
        title = "Local check complete",
        reasons = emptyList(),
        isWebUrl = true
    )

    private val suspicious = clean.copy(
        riskLevel = RiskLevel.SUSPICIOUS
    )

    private val noMatch = ReputationResult.NoKnownThreat(1000L)

    private val threat = ReputationResult.KnownThreat(
        setOf("SOCIAL_ENGINEERING"), 1000L
    )

    @Test
    fun noOnlineResultIsUnverified() {
        assertEquals(
            OverallRisk.UNVERIFIED,
            HybridRiskEngine.assess(clean).risk
        )
    }

    @Test
    fun cleanPlusNoMatchIsLowRisk() {
        assertEquals(
            OverallRisk.LOW_RISK,
            HybridRiskEngine.assess(clean, noMatch).risk
        )
    }

    @Test
    fun knownThreatHasHighestPriority() {
        assertEquals(
            OverallRisk.HIGH_RISK,
            HybridRiskEngine.assess(suspicious, threat).risk
        )
    }

    @Test
    fun noMatchDoesNotCancelLocalSuspicion() {
        assertEquals(
            OverallRisk.SUSPICIOUS,
            HybridRiskEngine.assess(suspicious, noMatch).risk
        )
    }

    @Test
    fun networkFailureIsNotLowRisk() {
        val offline = ReputationResult.Unavailable(
            ReputationFailure.NETWORK
        )

        assertEquals(
            OverallRisk.UNVERIFIED,
            HybridRiskEngine.assess(clean, offline).risk
        )
    }
}