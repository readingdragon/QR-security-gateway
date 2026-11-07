package com.qrsg.app.domain.analyzer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

class LocalUrlAnalyzerTest {
    private fun result(url: String) = LocalUrlAnalyzer.analyze(url)
    private fun hasRule(url: String, rule: HeuristicRuleId): Boolean =
        result(url).findings.any { it.id == rule }

    @Test fun httpsExampleIsLowRiskButNotGuaranteedSafe() {
        val r = result("https://example.com")
        assertEquals(RiskLevel.LOW_RISK, r.riskLevel)
        assertTrue(r.isWebUrl)
        assertEquals("example.com", r.host)
        assertTrue(r.findings.isEmpty())
        assertTrue(r.reasons.single().contains("not guarantee"))
    }

    @Test fun uppercaseHttpsIsAccepted() {
        assertEquals(RiskLevel.LOW_RISK, result("HTTPS://EXAMPLE.COM").riskLevel)
    }

    @Test fun trailingDotDomainIsNormalizedForRules() {
        assertEquals("example.com", result("https://EXAMPLE.com./").host)
    }

    @Test fun surroundingWhitespaceIsTrimmed() {
        assertEquals(RiskLevel.LOW_RISK, result("  https://example.com  ").riskLevel)
    }

    @Test fun httpIsFlagged() {
        assertTrue(hasRule("http://example.com", HeuristicRuleId.HTTP_SCHEME))
    }

    @Test fun httpIsSuspicious() {
        assertEquals(RiskLevel.SUSPICIOUS, result("http://example.com").riskLevel)
    }

    @Test fun shortenerIsFlagged() {
        assertTrue(hasRule("https://bit.ly/example", HeuristicRuleId.SHORTENER))
    }

    @Test fun wwwShortenerIsFlagged() {
        assertTrue(hasRule("https://www.tinyurl.com/abc", HeuristicRuleId.SHORTENER))
    }

    @Test fun shortenerSubstringDoesNotTrigger() {
        assertFalse(hasRule("https://bit.ly.evil.example/", HeuristicRuleId.SHORTENER))
    }

    @Test fun punycodeHostIsFlagged() {
        assertTrue(hasRule("https://xn--e1afmkfd.xn--p1ai", HeuristicRuleId.PUNYCODE_HOST))
    }

    @Test fun unicodeInternationalDomainIsFlagged() {
        val r = result("https://bücher.de/path")
        assertTrue(r.isWebUrl)
        assertEquals("xn--bcher-kva.de", r.host)
        assertTrue(r.findings.any { it.id == HeuristicRuleId.UNICODE_HOST })
        assertTrue(r.findings.any { it.id == HeuristicRuleId.PUNYCODE_HOST })
    }

    @Test fun loginPathIsFlagged() {
        assertTrue(hasRule("https://example.com/login", HeuristicRuleId.SENSITIVE_KEYWORD))
    }

    @Test fun loginInQueryIsFlagged() {
        assertTrue(hasRule("https://example.com/?action=verify", HeuristicRuleId.SENSITIVE_KEYWORD))
    }

    @Test fun encodedLoginPathIsFlagged() {
        assertTrue(hasRule("https://example.com/%6cogin", HeuristicRuleId.SENSITIVE_KEYWORD))
    }

    @Test fun loginAsPartOfOtherWordDoesNotTrigger() {
        assertFalse(hasRule("https://example.com/bloginators", HeuristicRuleId.SENSITIVE_KEYWORD))
    }

    @Test fun userinfoAtSignIsFlagged() {
        val r = result("https://example.com@evil.example/path")
        assertEquals("evil.example", r.host)
        assertTrue(r.findings.any { it.id == HeuristicRuleId.USER_INFO })
    }

    @Test fun userinfoWithPasswordIsFlagged() {
        assertTrue(hasRule("https://user:secret@host.example/", HeuristicRuleId.USER_INFO))
    }

    @Test fun atSignInPathIsNotUserinfo() {
        assertFalse(hasRule("https://example.com/path/@user", HeuristicRuleId.USER_INFO))
    }

    @Test fun ipv4HostIsFlagged() {
        assertTrue(hasRule("https://8.8.8.8", HeuristicRuleId.IPV4_HOST))
    }

    @Test fun privateIpv4IsNonPublic() {
        assertTrue(hasRule("https://192.168.1.1", HeuristicRuleId.NON_PUBLIC_DESTINATION))
        assertTrue(hasRule("https://10.0.0.9", HeuristicRuleId.NON_PUBLIC_DESTINATION))
        assertTrue(hasRule("https://172.17.0.1", HeuristicRuleId.NON_PUBLIC_DESTINATION))
    }

    @Test fun publicIpv4IsNotNonPublic() {
        assertFalse(hasRule("https://8.8.8.8", HeuristicRuleId.NON_PUBLIC_DESTINATION))
    }

    @Test fun localhostIsNonPublic() {
        assertTrue(hasRule("http://localhost:8080", HeuristicRuleId.NON_PUBLIC_DESTINATION))
    }

    @Test fun localMdnsDomainIsNonPublic() {
        assertTrue(hasRule("https://printer.local", HeuristicRuleId.NON_PUBLIC_DESTINATION))
    }

    @Test fun ipv6LoopbackIsFlagged() {
        val url = "http://[::1]/"
        assertTrue(hasRule(url, HeuristicRuleId.IPV6_HOST))
        assertTrue(hasRule(url, HeuristicRuleId.NON_PUBLIC_DESTINATION))
    }

    @Test fun ipv6GlobalIsNotNonPublic() {
        assertTrue(hasRule("https://[2606:4700:4700::1111]/", HeuristicRuleId.IPV6_HOST))
        assertFalse(hasRule("https://[2606:4700:4700::1111]/", HeuristicRuleId.NON_PUBLIC_DESTINATION))
    }

    @Test fun ipv6LinkLocalIsNonPublic() {
        assertTrue(hasRule("https://[fe90::1]/", HeuristicRuleId.NON_PUBLIC_DESTINATION))
    }

    @Test fun ipv4MappedIpv6LoopbackIsNonPublic() {
        assertTrue(hasRule("https://[::ffff:127.0.0.1]/", HeuristicRuleId.NON_PUBLIC_DESTINATION))
    }

    @Test fun ipv4MappedIpv6PublicIsNotNonPublic() {
        assertFalse(hasRule("https://[::ffff:8.8.8.8]/", HeuristicRuleId.NON_PUBLIC_DESTINATION))
    }

    @Test fun numericHostIsFlagged() {
        assertTrue(hasRule("https://2130706433/", HeuristicRuleId.NUMERIC_HOST))
        assertTrue(hasRule("https://0x7f000001/", HeuristicRuleId.NUMERIC_HOST))
    }

    @Test fun leadingZeroIpv4IsFlagged() {
        assertTrue(hasRule("https://0177.0.0.1/", HeuristicRuleId.LEADING_ZERO_IPV4))
    }

    @Test fun nonStandardPortIsFlagged() {
        assertTrue(hasRule("https://example.com:8443", HeuristicRuleId.NON_STANDARD_PORT))
    }

    @Test fun standardPortsDoNotTrigger() {
        assertFalse(hasRule("http://example.com:80", HeuristicRuleId.NON_STANDARD_PORT))
        assertFalse(hasRule("https://example.com:443", HeuristicRuleId.NON_STANDARD_PORT))
    }

    @Test fun tooManySubdomainsAreFlagged() {
        assertTrue(hasRule("https://a.b.c.d.example.com", HeuristicRuleId.MANY_SUBDOMAINS))
    }

    @Test fun ordinarySubdomainDoesNotTrigger() {
        assertFalse(hasRule("https://www.example.com", HeuristicRuleId.MANY_SUBDOMAINS))
    }

    @Test fun longUrlIsFlagged() {
        assertTrue(hasRule("https://example.com/" + "x".repeat(210), HeuristicRuleId.LONG_URL))
    }

    @Test fun doubleEncodingIsFlagged() {
        assertTrue(hasRule("https://example.com/%252e%252e", HeuristicRuleId.DOUBLE_ENCODING))
    }

    @Test fun normalPercentEncodingNotDoubleEncoding() {
        assertFalse(hasRule("https://example.com/%20", HeuristicRuleId.DOUBLE_ENCODING))
    }

    @Test fun emptyValueIsUnverified() {
        val r = result("")
        assertEquals(RiskLevel.UNVERIFIED, r.riskLevel)
        assertFalse(r.isWebUrl)
        assertNull(r.host)
    }

    @Test fun blankValueIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("   ").riskLevel)
    }

    @Test fun plainTextIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("not-a-url").riskLevel)
    }

    @Test fun relativeUrlIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("//example.com").riskLevel)
    }

    @Test fun javascriptSchemeIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("javascript:alert(1)").riskLevel)
    }

    @Test fun intentSchemeIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("intent://example.com/#Intent;end").riskLevel)
    }

    @Test fun fileSchemeIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("file:///etc/passwd").riskLevel)
    }

    @Test fun wifiPayloadIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("WIFI:T:WPA;S:router;P:secret;;").riskLevel)
    }

    @Test fun hostlessHttpIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("https:///login").riskLevel)
    }

    @Test fun malformedIpv4IsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("https://999.999.999.999/").riskLevel)
    }

    @Test fun invalidPortIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("https://example.com:abc/").riskLevel)
    }

    @Test fun portOutOfRangeIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("https://example.com:65536/").riskLevel)
    }

    @Test fun portZeroIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("https://example.com:0/").riskLevel)
    }

    @Test fun emptyPortIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("https://example.com:/").riskLevel)
    }

    @Test fun newlineInjectionIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("https://example.com\n.evil.example").riskLevel)
    }

    @Test fun spaceInsideUrlIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("https://exa mple.com").riskLevel)
    }

    @Test fun oversizedUrlIsUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("https://example.com/" + "a".repeat(8200)).riskLevel)
    }

    @Test fun multipleAtSignsAreUnverified() {
        assertEquals(RiskLevel.UNVERIFIED, result("https://a@b@evil.example/").riskLevel)
    }

    @Test fun findingsHaveStableIdsAndNoDuplicates() {
        val r = result("http://user@bit.ly/login")
        assertEquals(RiskLevel.SUSPICIOUS, r.riskLevel)
        assertTrue(r.findings.size >= 3)
        assertEquals(r.findings.size, r.findings.map { it.id }.toSet().size)
        assertEquals(r.findings.map { it.description }, r.reasons)
    }

    @Test fun randomQrPayloadsNeverCrashTheAnalyzer() {
        val random = Random(42)
        val alphabet = "abcXYZ12309:/?@.&=%[]-# \n\tюあ"
        repeat(1_000) {
            val payload = buildString {
                repeat(random.nextInt(0, 120)) { append(alphabet[random.nextInt(alphabet.length)]) }
            }
            val r = result(payload)
            assertTrue(r.reasons.isNotEmpty())
            if (!r.isWebUrl) assertEquals(RiskLevel.UNVERIFIED, r.riskLevel)
        }
    }

    @Test fun repeatedAnalysisIsDeterministic() {
        val url = "https://xn--e1afmkfd.xn--p1ai/login"
        assertEquals(result(url), result(url))
    }

    @Test fun noNetworkInformationIsImpliedByLowRisk() {
        val r = result("https://example.com")
        assertNotNull(r.reasons.single())
        assertTrue(r.reasons.single().contains("reputation"))
    }
}
