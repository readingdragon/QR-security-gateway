package com.qrsg.app.domain.analyzer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalUrlAnalyzerTest {

    @Test
    fun ordinaryHttpsUrl_hasNoLocalWarning() {
        val result = LocalUrlAnalyzer.analyze("https://example.com")

        assertEquals(RiskLevel.LOW_RISK, result.riskLevel)
        assertTrue(result.isWebUrl)
        assertTrue(result.reasons.isNotEmpty())
    }

    @Test
    fun httpUrl_isSuspicious() {
        val result = LocalUrlAnalyzer.analyze("http://example.com")

        assertEquals(RiskLevel.SUSPICIOUS, result.riskLevel)
        assertTrue(result.reasons.any { it.contains("HTTP") })
    }

    @Test
    fun shortenedUrl_isSuspicious() {
        val result = LocalUrlAnalyzer.analyze("https://bit.ly/example")

        assertEquals(RiskLevel.SUSPICIOUS, result.riskLevel)
        assertTrue(result.reasons.any { it.contains("clipped") })
    }

    @Test
    fun punycodeDomain_isSuspicious() {
        val result = LocalUrlAnalyzer.analyze("https://xn--e1afmkfd.xn--p1ai")

        assertEquals(RiskLevel.SUSPICIOUS, result.riskLevel)
        assertTrue(result.reasons.any { it.contains("Punycode") })
    }

    @Test
    fun urlWithLoginPath_isSuspicious() {
        val result = LocalUrlAnalyzer.analyze("https://example.com/login")

        assertEquals(RiskLevel.SUSPICIOUS, result.riskLevel)
    }

    @Test
    fun plainText_isUnverified() {
        val result = LocalUrlAnalyzer.analyze("not-a-url")

        assertEquals(RiskLevel.UNVERIFIED, result.riskLevel)
        assertFalse(result.isWebUrl)
    }

    @Test
    fun emptyValue_isUnverified() {
        val result = LocalUrlAnalyzer.analyze("")

        assertEquals(RiskLevel.UNVERIFIED, result.riskLevel)
        assertFalse(result.isWebUrl)
    }

    @Test
    fun urlWithUserInfo_isSuspicious() {
        val result = LocalUrlAnalyzer.analyze("https://example.com@evil.example/path")

        assertEquals(RiskLevel.SUSPICIOUS, result.riskLevel)
        assertTrue(result.reasons.any { it.contains("@") })
    }
}
