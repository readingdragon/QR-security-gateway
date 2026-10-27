package com.qrsg.app.domain.analyzer

import java.net.URI

enum class RiskLevel {
    LOW_RISK,
    SUSPICIOUS,
    UNVERIFIED,
}

data class UrlAnalysisResult(
    val riskLevel: RiskLevel,
    val title: String,
    val reasons: List<String>,
    val isWebUrl: Boolean,
)

object LocalUrlAnalyzer {

    private val knownShorteners = setOf(
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "ow.ly",
        "buff.ly",
        "cutt.ly",
        "rb.gy",
    )

    private val suspiciousWords = listOf(
        "login",
        "verify",
        "verification",
        "password",
        "wallet",
        "account",
        "signin",
        "secure",
        "update-payment",
    )

    fun analyze(rawValue: String): UrlAnalysisResult {
        val value = rawValue.trim()

        if (value.isBlank()) {
            return unverified("The QR code does not contain text.")
        }

        if (value.any { it.isWhitespace() }) {
            return unverified("The content contains spaces and does not look like a valid URL.")
        }

        val uri = try {
            URI(value)
        } catch (_: Exception) {
            return unverified("Failed to parse the address.")
        }

        val scheme = uri.scheme?.lowercase()
        val host = uri.host?.lowercase()?.trimEnd('.')

        if (scheme !in setOf("http", "https") || host.isNullOrBlank()) {
            return unverified(
                "This is not a complete HTTP/HTTPS web address. Do not open it until you have verified its content."
            )
        }

        val reasons = mutableListOf<String>()

        if (scheme == "http") {
            reasons += "The connection uses HTTP without HTTPS encryption."
        }

        if (uri.rawAuthority?.contains('@') == true) {
            reasons += "The address contains an @ symbol in the domain part — check the actual host."
        }

        if (host.startsWith("xn--") || host.split('.').any { it.startsWith("xn--") }) {
            reasons += "The domain contains Punycode (xn--); check whether a similar-looking character is being used for masking."
        }

        if (IPV4.matches(host)) {
            reasons += "An IPv4 address is used instead of a standard domain name."
        }

        if (host in knownShorteners) {
            reasons += "A link-shortening service was used; the final destination is unknown."
        }

        if (host.split('.').size >= 5) {
            reasons += "The domain has many levels of subdomains."
        }

        if (value.length > 200) {
            reasons += "The URL is unusually long."
        }

        val pathAndQuery = "${uri.rawPath.orEmpty()}?${uri.rawQuery.orEmpty()}"
            .lowercase()

        if (suspiciousWords.any(pathAndQuery::contains)) {
            reasons += "The path or parameters contain words that frequently appear in login or account verification requests."
        }

        return if (reasons.isEmpty()) {
            UrlAnalysisResult(
                riskLevel = RiskLevel.LOW_RISK,
                title = "No obvious local signs of risk were found.",
                reasons = listOf(
                    "This does not confirm the safety of the site. The URL's reputation has not yet been checked."
                ),
                isWebUrl = true,
            )
        } else {
            UrlAnalysisResult(
                riskLevel = RiskLevel.SUSPICIOUS,
                title = "Signs have been detected that are worth checking",
                reasons = reasons,
                isWebUrl = true,
            )
        }
    }

    private fun unverified(reason: String) = UrlAnalysisResult(
        riskLevel = RiskLevel.UNVERIFIED,
        title = "Could not verify the web address",
        reasons = listOf(reason),
        isWebUrl = false,
    )

    private val IPV4 = Regex("""^(?:\d{1,3}\.){3}\d{1,3}$""")
}
