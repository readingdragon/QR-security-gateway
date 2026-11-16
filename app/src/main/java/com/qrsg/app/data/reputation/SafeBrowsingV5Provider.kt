package com.qrsg.app.data.reputation

import com.qrsg.app.domain.analyzer.HeuristicRuleId
import com.qrsg.app.domain.analyzer.LocalUrlAnalyzer
import com.qrsg.app.domain.reputation.ReputationFailure
import com.qrsg.app.domain.reputation.ReputationProvider
import com.qrsg.app.domain.reputation.ReputationResult
import com.qrsg.app.domain.reputation.SkipReason
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.SocketTimeoutException
import java.net.URLEncoder
import javax.net.ssl.HttpsURLConnection
import java.net.URL

/** Fixed endpoint only: this code never opens the scanned website itself. */
internal interface SafeBrowsingTransport {
    fun lookup(url: String, apiKey: String): HttpLookupResponse
}

internal data class HttpLookupResponse(val code: Int, val body: ByteArray)

/** Android identity is passed only as Google API request metadata, not used for authorization. */
data class AndroidKeyIdentity(val packageName: String, val certSha1: String)

internal class GoogleHttpsTransport(
    private val identity: AndroidKeyIdentity?
) : SafeBrowsingTransport {

    override fun lookup(
        url: String,
        apiKey: String
    ): HttpLookupResponse {
        val request = URL(
            "https://safebrowsing.googleapis.com/v5/urls:search" +
                "?urls=${URLEncoder.encode(url, "UTF-8")}"
        )

        val connection = request.openConnection()
            as HttpsURLConnection

        try {
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 5_000
            connection.readTimeout = 7_000

            connection.setRequestProperty(
                "Accept",
                "application/x-protobuf"
            )
            connection.setRequestProperty(
                "X-Goog-Api-Key",
                apiKey
            )

            identity?.let {
                connection.setRequestProperty(
                    "X-Android-Package",
                    it.packageName
                )
                connection.setRequestProperty(
                    "X-Android-Cert",
                    it.certSha1
                )
            }

            val status = connection.responseCode

            val stream = if (status in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
            }

            val body = stream?.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(4096)

                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break

                    if (output.size() + n > 262_144) {
                        throw IllegalStateException(
                            "Response too large"
                        )
                    }

                    output.write(buffer, 0, n)
                }

                output.toByteArray()
            } ?: ByteArray(0)

            return HttpLookupResponse(status, body)

        } finally {
            connection.disconnect()
        }
    }
}

/**
 * Safe Browsing v5, URLs Search method. NON-COMMERCIAL use only.
 * Sends the FULL URL (without fragment) to Google.
 */
class SafeBrowsingV5Provider internal constructor(
    private val apiKey: String,
    private val transport: SafeBrowsingTransport,
    private val nowMillis: () -> Long,
) : ReputationProvider {

    constructor(apiKey: String, androidIdentity: AndroidKeyIdentity? = null) :
        this(apiKey, GoogleHttpsTransport(androidIdentity), System::currentTimeMillis)

    private data class CacheEntry(val result: ReputationResult, val expiresAt: Long)
    private val cache = object : LinkedHashMap<String, CacheEntry>(32, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CacheEntry>): Boolean = size > 256
    }

    override suspend fun checkUrl(rawUrl: String): ReputationResult {
        val local = LocalUrlAnalyzer.analyze(rawUrl)
        if (!local.isWebUrl) return ReputationResult.Skipped(SkipReason.NOT_A_WEB_URL)
        if (local.findings.any { it.id == HeuristicRuleId.NON_PUBLIC_DESTINATION }) {
            return ReputationResult.Skipped(SkipReason.NON_PUBLIC_DESTINATION)
        }
        if (local.findings.any { it.id == HeuristicRuleId.USER_INFO }) {
            return ReputationResult.Skipped(SkipReason.URL_CONTAINS_USER_INFO)
        }
        if (local.findings.any { it.id in setOf(HeuristicRuleId.NUMERIC_HOST, HeuristicRuleId.LEADING_ZERO_IPV4) }) {
            return ReputationResult.Skipped(SkipReason.AMBIGUOUS_NUMERIC_HOST)
        }
        if (apiKey.isBlank()) return ReputationResult.Unavailable(ReputationFailure.NOT_CONFIGURED)

        // Fragment identifiers do not travel to HTTP servers and are unnecessary to check.
        val url = rawUrl.trim().substringBefore('#')
        synchronized(cache) {
            val cached = cache[url]
            if (cached != null && cached.expiresAt > nowMillis()) {
                return when (val result = cached.result) {
                    is ReputationResult.KnownThreat -> result.copy(fromCache = true)
                    is ReputationResult.NoKnownThreat -> result.copy(fromCache = true)
                    else -> result
                }
            }
            if (cached != null) cache.remove(url)
        }

        return withContext(Dispatchers.IO) {
            try {
                val response = transport.lookup(url, apiKey)
                if (response.code != 200) {
                    val failure = when (response.code) {
                        401, 403 -> ReputationFailure.AUTHENTICATION
                        429 -> ReputationFailure.RATE_LIMITED
                        in 500..599 -> ReputationFailure.PROVIDER_ERROR
                        else -> ReputationFailure.MALFORMED_RESPONSE
                    }
                    return@withContext ReputationResult.Unavailable(failure)
                }
                val parsed = parseResponse(response.body)
                val now = nowMillis()
                val result: ReputationResult = if (parsed.threatTypes.isEmpty()) {
                    ReputationResult.NoKnownThreat(now)
                } else {
                    ReputationResult.KnownThreat(parsed.threatTypes, now)
                }
                // Google's terms: known-threat warnings must use data refreshed within 30 minutes.
                val maxTtl = if (result is ReputationResult.KnownThreat) 30 * 60 * 1_000L
                    else 24 * 60 * 60 * 1_000L
                val ttl = parsed.cacheDurationMs.coerceAtMost(maxTtl)
                if (ttl > 0) synchronized(cache) { cache[url] = CacheEntry(result, now + ttl) }
                result
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: SocketTimeoutException) {
                ReputationResult.Unavailable(ReputationFailure.NETWORK)
            } catch (_: java.io.IOException) {
                ReputationResult.Unavailable(ReputationFailure.NETWORK)
            } catch (_: Exception) {
                ReputationResult.Unavailable(
                    ReputationFailure.MALFORMED_RESPONSE
                )
            }
        }
    }

    internal data class ParsedResponse(val threatTypes: Set<String>, val cacheDurationMs: Long)

    internal fun parseResponse(
        raw: ByteArray
    ): ParsedResponse {
        val parsed = try {
            SafeBrowsingProtobufDecoder.decode(raw)
        } catch (e: java.io.IOException) {
            throw IllegalArgumentException(
                "Invalid protobuf", e
            )
        }

        return ParsedResponse(
            parsed.threatTypes,
            parsed.cacheDurationMs
        )
    }
}
