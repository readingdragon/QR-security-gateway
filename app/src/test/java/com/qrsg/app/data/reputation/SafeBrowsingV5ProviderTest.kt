package com.qrsg.app.data.reputation

import com.qrsg.app.domain.reputation.ReputationFailure
import com.qrsg.app.domain.reputation.ReputationResult
import com.qrsg.app.domain.reputation.SkipReason
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SafeBrowsingV5ProviderTest {
    private class FakeTransport(var response: HttpLookupResponse) : SafeBrowsingTransport {
        var calls = 0
        var lastUrl: String? = null
        override fun lookup(url: String, apiKey: String): HttpLookupResponse {
            calls++
            lastUrl = url
            return response
        }
    }

    private val noThreat = HttpLookupResponse(200, """{"threats":[],"cacheDuration":"60s"}""")
    private val phishing = HttpLookupResponse(200,
        """{"threats":[{"url":"https://example.com/","threatTypes":["SOCIAL_ENGINEERING"]}],"cacheDuration":"60s"}""")

    @Test fun noKnownThreatIsNotLabeledSafe() = runTest {
        val transport = FakeTransport(noThreat)
        val r = SafeBrowsingV5Provider("demo-key", transport, { 1000 }).checkUrl("https://example.com/")
        assertTrue(r is ReputationResult.NoKnownThreat)
        assertEquals(1, transport.calls)
    }

    @Test fun phishingMatchProducesKnownThreat() = runTest {
        val r = SafeBrowsingV5Provider("demo-key", FakeTransport(phishing), { 1000 })
            .checkUrl("https://example.com/")
        assertEquals(setOf("SOCIAL_ENGINEERING"), (r as ReputationResult.KnownThreat).threatTypes)
    }

    @Test fun noKeyDoesNotMakeNetworkRequest() = runTest {
        val t = FakeTransport(noThreat)
        val r = SafeBrowsingV5Provider("", t, { 1000 }).checkUrl("https://example.com/")
        assertEquals(ReputationResult.Unavailable(ReputationFailure.NOT_CONFIGURED), r)
        assertEquals(0, t.calls)
    }

    @Test fun nonWebContentIsNotUploaded() = runTest {
        val t = FakeTransport(noThreat)
        val r = SafeBrowsingV5Provider("demo-key", t, { 1000 }).checkUrl("WIFI:T:WPA;S:X;P:X;;")
        assertEquals(ReputationResult.Skipped(SkipReason.NOT_A_WEB_URL), r)
        assertEquals(0, t.calls)
    }

    @Test fun privateIpIsNotUploaded() = runTest {
        val t = FakeTransport(noThreat)
        val r = SafeBrowsingV5Provider("demo-key", t, { 1000 }).checkUrl("http://192.168.1.1/")
        assertEquals(ReputationResult.Skipped(SkipReason.NON_PUBLIC_DESTINATION), r)
        assertEquals(0, t.calls)
    }

    @Test fun userinfoIsNotUploaded() = runTest {
        val t = FakeTransport(noThreat)
        val r = SafeBrowsingV5Provider("demo-key", t, { 1000 }).checkUrl("https://login:pass@example.com/")
        assertEquals(ReputationResult.Skipped(SkipReason.URL_CONTAINS_USER_INFO), r)
        assertEquals(0, t.calls)
    }

    @Test fun obfuscatedNumericalHostIsNotUploaded() = runTest {
        val t = FakeTransport(noThreat)
        val r = SafeBrowsingV5Provider("demo-key", t, { 1000 }).checkUrl("https://2130706433/")
        assertEquals(ReputationResult.Skipped(SkipReason.AMBIGUOUS_NUMERIC_HOST), r)
        assertEquals(0, t.calls)
    }

    @Test fun fragmentsAreNotTransmitted() = runTest {
        val t = FakeTransport(noThreat)
        SafeBrowsingV5Provider("demo-key", t, { 1000 }).checkUrl("https://example.com/path#token")
        assertEquals("https://example.com/path", t.lastUrl)
    }

    @Test fun aPositiveAndNegativeResultAreCached() = runTest {
        var time = 1000L
        val t = FakeTransport(phishing)
        val provider = SafeBrowsingV5Provider("demo-key", t, { time })
        provider.checkUrl("https://example.com/")
        val hit = provider.checkUrl("https://example.com/")
        assertTrue((hit as ReputationResult.KnownThreat).fromCache)
        assertEquals(1, t.calls)
        t.response = noThreat
        time = 62_000L
        val miss = provider.checkUrl("https://example.com/")
        assertTrue(miss is ReputationResult.NoKnownThreat)
        val again = provider.checkUrl("https://example.com/")
        assertTrue((again as ReputationResult.NoKnownThreat).fromCache)
        assertEquals(2, t.calls)
    }

    @Test fun cacheDurationZeroNeverCaches() = runTest {
        val t = FakeTransport(HttpLookupResponse(200, """{"cacheDuration":"0s"}"""))
        val provider = SafeBrowsingV5Provider("demo-key", t, { 123L })
        provider.checkUrl("https://example.com/")
        provider.checkUrl("https://example.com/")
        assertEquals(2, t.calls)
    }
    
    @Test
    fun missingCacheDurationReturnsNoThreatWithoutCaching() = runTest {
        val transport = FakeTransport(
            HttpLookupResponse(200, """{"threats":[]}""")
        )

        val provider = SafeBrowsingV5Provider(
            "demo-key", transport, { 1000L }
        )

        val result = provider.checkUrl("https://example.com/")

        assertTrue(
            "Actual result: $result",
            result is ReputationResult.NoKnownThreat
        )

        provider.checkUrl("https://example.com/")

        assertEquals(2, transport.calls)
    }

    @Test
    fun emptyJsonResponseMeansNoKnownThreat() = runTest {
        val transport = FakeTransport(
            HttpLookupResponse(200, "{}")
        )

        val provider = SafeBrowsingV5Provider(
            "demo-key", transport, { 1000L }
        )

        val result = provider.checkUrl("https://example.com/")

        assertTrue(
            "Actual result: $result",
            result is ReputationResult.NoKnownThreat
        )
    }

    @Test fun expiredCachedThreatIsNotShown() = runTest {
        var time = 0L
        val t = FakeTransport(phishing)
        val provider = SafeBrowsingV5Provider("demo-key", t, { time })
        provider.checkUrl("https://example.com/")
        time = 61_000L
        t.response = noThreat
        assertTrue(provider.checkUrl("https://example.com/") is ReputationResult.NoKnownThreat)
    }

    @Test fun authenticationErrorsAreNotClean() = runTest {
        val r = SafeBrowsingV5Provider("demo-key", FakeTransport(HttpLookupResponse(403, "")), { 0 })
            .checkUrl("https://example.com/")
        assertEquals(ReputationResult.Unavailable(ReputationFailure.AUTHENTICATION), r)
    }

    @Test fun rateLimitIsNotClean() = runTest {
        val r = SafeBrowsingV5Provider("demo-key", FakeTransport(HttpLookupResponse(429, "")), { 0 })
            .checkUrl("https://example.com/")
        assertEquals(ReputationResult.Unavailable(ReputationFailure.RATE_LIMITED), r)
    }

    @Test fun providerErrorIsNotClean() = runTest {
        val r = SafeBrowsingV5Provider("demo-key", FakeTransport(HttpLookupResponse(502, "")), { 0 })
            .checkUrl("https://example.com/")
        assertEquals(ReputationResult.Unavailable(ReputationFailure.PROVIDER_ERROR), r)
    }

    @Test fun invalidJsonIsUnknownNotClean() = runTest {
        val r = SafeBrowsingV5Provider("demo-key", FakeTransport(HttpLookupResponse(200, "oops")), { 0 })
            .checkUrl("https://example.com/")
        assertEquals(ReputationResult.Unavailable(ReputationFailure.MALFORMED_RESPONSE), r)
    }

    // @Test fun missingCacheDurationIsUnknownNotClean() = runTest {
    //     val r = SafeBrowsingV5Provider("demo-key", FakeTransport(HttpLookupResponse(200, """{"threats":[]}""")), { 0 })
    //         .checkUrl("https://example.com/")
    //     assertEquals(ReputationResult.Unavailable(ReputationFailure.MALFORMED_RESPONSE), r)
    // }

    @Test fun malformedThreatIsUnknownNotClean() = runTest {
        val r = SafeBrowsingV5Provider("demo-key",
            FakeTransport(HttpLookupResponse(200, """{"cacheDuration":"60s","threats":[{}]}""")), { 0 })
            .checkUrl("https://example.com/")
        assertEquals(ReputationResult.Unavailable(ReputationFailure.MALFORMED_RESPONSE), r)
    }

    @Test fun googleMayOmitEmptyThreatArray() = runTest {
        val r = SafeBrowsingV5Provider("demo-key",
            FakeTransport(HttpLookupResponse(200, """{"cacheDuration":"15.5s"}""")), { 0 })
            .checkUrl("https://example.com/")
        assertTrue(r is ReputationResult.NoKnownThreat)
    }

    @Test fun allReportedThreatTypesArePreserved() = runTest {
        val response = HttpLookupResponse(200,
            """{"cacheDuration":"60s","threats":[{"url":"https://example.com/","threatTypes":["SOCIAL_ENGINEERING","MALWARE"]}]}""")
        val r = SafeBrowsingV5Provider("demo-key", FakeTransport(response), { 0 })
            .checkUrl("https://example.com/") as ReputationResult.KnownThreat
        assertEquals(setOf("SOCIAL_ENGINEERING", "MALWARE"), r.threatTypes)
        assertFalse(r.fromCache)
    }
}
