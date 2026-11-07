package com.qrsg.app.domain.analyzer

/** A local verdict, NOT an external threat-intelligence verdict. */
enum class RiskLevel {
    LOW_RISK,
    SUSPICIOUS,
    UNVERIFIED,
}

/** Stable identifiers for localization, instrumentation and regression tests. */
enum class HeuristicRuleId {
    HTTP_SCHEME,
    USER_INFO,
    PUNYCODE_HOST,
    UNICODE_HOST,
    IPV4_HOST,
    IPV6_HOST,
    NON_PUBLIC_DESTINATION,
    NUMERIC_HOST,
    SHORTENER,
    MANY_SUBDOMAINS,
    LONG_URL,
    SENSITIVE_KEYWORD,
    DOUBLE_ENCODING,
    NON_STANDARD_PORT,
    LEADING_ZERO_IPV4,
}

enum class FindingSeverity { LOW, MEDIUM, HIGH }

data class HeuristicFinding(
    val id: HeuristicRuleId,
    val severity: FindingSeverity,
    val description: String,
)

/** Backwards compatible with the original scanner usage: riskLevel/title/reasons/isWebUrl. */
data class UrlAnalysisResult(
    val riskLevel: RiskLevel,
    val title: String,
    val reasons: List<String>,
    val isWebUrl: Boolean,
    val host: String? = null,
    val findings: List<HeuristicFinding> = emptyList(),
)
