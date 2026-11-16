package com.qrsg.app.data.reputation

import com.google.protobuf.CodedOutputStream
import com.qrsg.app.domain.reputation.ReputationFailure
import com.qrsg.app.domain.reputation.ReputationResult
import com.qrsg.app.domain.reputation.SkipReason
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream

class SafeBrowsingV5ProviderTest {

    private class Fake(var response: HttpLookupResponse) : SafeBrowsingTransport {
        var calls = 0
        var lastUrl = ""

        override fun lookup(url: String, apiKey: String): HttpLookupResponse {
            calls++
            lastUrl = url
            return response
        }
    }

    private fun wire(block: (CodedOutputStream) -> Unit): ByteArray {
        val buffer = ByteArrayOutputStream()
        val output = CodedOutputStream.newInstance(buffer)
        block(output)
        output.flush()
        return buffer.toByteArray()
    }

    // Builds a real SearchUrlsResponse protobuf message.
    private fun response(
        types: List<Int> = emptyList(),
        seconds: Long? = 60L,
        nanos: Int = 0
    ): HttpLookupResponse = HttpLookupResponse(200, wire { outer ->
        if (types.isNotEmpty()) {
            val threat = wire { inner ->
                inner.writeString(1, "https://example.com/")
                types.forEach { inner.writeEnum(2, it) }
            }
            outer.writeByteArray(1, threat)
        }
        if (seconds != null) {
            val duration = wire { inner ->
                inner.writeInt64(1, seconds)
                if (nanos != 0) inner.writeInt32(2, nanos)
            }
            outer.writeByteArray(2, duration)
        }
    })

    private val clean get() = response()
    private val phishing get() = response(types = listOf(2))

    @Test fun cleanUrl() = runTest {
        val t = Fake(clean)
        val result = SafeBrowsingV5Provider("key", t, { 1000L })
            .checkUrl("https://example.com/")

        assertTrue("$result", result is ReputationResult.NoKnownThreat)
        assertEquals(1, t.calls)
    }

    @Test fun phishingDetected() = runTest {
        val result = SafeBrowsingV5Provider("key", Fake(phishing), { 0L })
            .checkUrl("https://example.com/")

        assertEquals(
            setOf("SOCIAL_ENGINEERING"),
            (result as ReputationResult.KnownThreat).threatTypes
        )
    }

    @Test fun malwareDetected() = runTest {
        val result = SafeBrowsingV5Provider(
            "key", Fake(response(types = listOf(1))), { 0L }
        ).checkUrl("https://example.com/")

        assertEquals(
            setOf("MALWARE"),
            (result as ReputationResult.KnownThreat).threatTypes
        )
    }

    @Test fun multipleThreatTypes() = runTest {
        val result = SafeBrowsingV5Provider(
            "key", Fake(response(types = listOf(1, 2))), { 0L }
        ).checkUrl("https://example.com/")

        assertEquals(
            setOf("MALWARE", "SOCIAL_ENGINEERING"),
            (result as ReputationResult.KnownThreat).threatTypes
        )
    }

    @Test fun fiveByteProtobufResponse() {
        val raw = byteArrayOf(
            0x12, 0x03, 0x08, 0xB3.toByte(), 0x02
        )
        val decoded = SafeBrowsingProtobufDecoder.decode(raw)

        assertTrue(decoded.threatTypes.isEmpty())
        assertEquals(307_000L, decoded.cacheDurationMs)
    }

    @Test fun fractionalCacheDuration() {
        val decoded = SafeBrowsingProtobufDecoder.decode(
            response(seconds = 15L, nanos = 500_000_000).body
        )
        assertEquals(15_500L, decoded.cacheDurationMs)
    }

    @Test fun missingCacheDurationDoesNotCache() = runTest {
        val t = Fake(response(seconds = null))
        val provider = SafeBrowsingV5Provider("key", t, { 1000L })

        assertTrue(provider.checkUrl("https://example.com/")
            is ReputationResult.NoKnownThreat)

        provider.checkUrl("https://example.com/")
        assertEquals(2, t.calls)
    }

    @Test fun positiveCacheAndExpiration() = runTest {
        var now = 1000L
        val t = Fake(phishing)
        val provider = SafeBrowsingV5Provider("key", t, { now })

        assertTrue(provider.checkUrl("https://example.com/")
            is ReputationResult.KnownThreat)

        val cached = provider.checkUrl("https://example.com/")
            as ReputationResult.KnownThreat

        assertTrue(cached.fromCache)
        assertEquals(1, t.calls)

        now += 61_000L
        t.response = clean

        assertTrue(provider.checkUrl("https://example.com/")
            is ReputationResult.NoKnownThreat)
        assertEquals(2, t.calls)
    }

    @Test fun negativeCacheWorks() = runTest {
        val t = Fake(clean)
        val provider = SafeBrowsingV5Provider("key", t, { 1000L })

        provider.checkUrl("https://example.com/")
        val result = provider.checkUrl("https://example.com/")
            as ReputationResult.NoKnownThreat

        assertTrue(result.fromCache)
        assertEquals(1, t.calls)
    }

    @Test fun malformedProtobufIsUnknown() = runTest {
        val corrupt = byteArrayOf(
            0x12, 0x03, 0x08, 0x80.toByte()
        )
        val result = SafeBrowsingV5Provider(
            "key", Fake(HttpLookupResponse(200, corrupt)), { 0L }
        ).checkUrl("https://example.com/")

        assertEquals(
            ReputationResult.Unavailable(ReputationFailure.MALFORMED_RESPONSE),
            result
        )
    }

    @Test fun jsonIsNotProtobuf() = runTest {
        val result = SafeBrowsingV5Provider(
            "key",
            Fake(HttpLookupResponse(200, "{}".toByteArray())),
            { 0L }
        ).checkUrl("https://example.com/")

        assertEquals(
            ReputationResult.Unavailable(ReputationFailure.MALFORMED_RESPONSE),
            result
        )
    }

    @Test fun malformedThreatIsRejected() = runTest {
        val threat = wire { it.writeString(1, "https://example.com/") }
        val raw = wire { it.writeByteArray(1, threat) }

        val result = SafeBrowsingV5Provider(
            "key", Fake(HttpLookupResponse(200, raw)), { 0L }
        ).checkUrl("https://example.com/")

        assertEquals(
            ReputationResult.Unavailable(ReputationFailure.MALFORMED_RESPONSE),
            result
        )
    }

    @Test fun noApiKey() = runTest {
        val t = Fake(clean)
        val result = SafeBrowsingV5Provider("", t, { 0L })
            .checkUrl("https://example.com/")

        assertEquals(
            ReputationResult.Unavailable(ReputationFailure.NOT_CONFIGURED),
            result
        )
        assertEquals(0, t.calls)
    }

    @Test fun privateIpNotUploaded() = runTest {
        val t = Fake(clean)
        val result = SafeBrowsingV5Provider("key", t, { 0L })
            .checkUrl("http://192.168.1.1/")

        assertEquals(
            ReputationResult.Skipped(SkipReason.NON_PUBLIC_DESTINATION),
            result
        )
        assertEquals(0, t.calls)
    }

    @Test fun nonWebContentNotUploaded() = runTest {
        val t = Fake(clean)
        val result = SafeBrowsingV5Provider("key", t, { 0L })
            .checkUrl("WIFI:T:WPA;S:TEST;P:TEST;;")

        assertEquals(
            ReputationResult.Skipped(SkipReason.NOT_A_WEB_URL),
            result
        )
        assertEquals(0, t.calls)
    }

    @Test fun userInfoNotUploaded() = runTest {
        val t = Fake(clean)
        val result = SafeBrowsingV5Provider("key", t, { 0L })
            .checkUrl("https://user:pass@example.com/")

        assertEquals(
            ReputationResult.Skipped(SkipReason.URL_CONTAINS_USER_INFO),
            result
        )
        assertEquals(0, t.calls)
    }

    @Test fun fragmentNotUploaded() = runTest {
        val t = Fake(clean)
        SafeBrowsingV5Provider("key", t, { 0L })
            .checkUrl("https://example.com/path#secret")

        assertEquals("https://example.com/path", t.lastUrl)
    }

    @Test fun authenticationFailure() = runTest {
        val result = SafeBrowsingV5Provider(
            "key", Fake(HttpLookupResponse(403, byteArrayOf())), { 0L }
        ).checkUrl("https://example.com/")

        assertEquals(
            ReputationResult.Unavailable(ReputationFailure.AUTHENTICATION),
            result
        )
    }

    @Test fun rateLimitFailure() = runTest {
        val result = SafeBrowsingV5Provider(
            "key", Fake(HttpLookupResponse(429, byteArrayOf())), { 0L }
        ).checkUrl("https://example.com/")

        assertEquals(
            ReputationResult.Unavailable(ReputationFailure.RATE_LIMITED),
            result
        )
    }

    @Test fun serverFailure() = runTest {
        val result = SafeBrowsingV5Provider(
            "key", Fake(HttpLookupResponse(503, byteArrayOf())), { 0L }
        ).checkUrl("https://example.com/")

        assertEquals(
            ReputationResult.Unavailable(ReputationFailure.PROVIDER_ERROR),
            result
        )
    }
}
