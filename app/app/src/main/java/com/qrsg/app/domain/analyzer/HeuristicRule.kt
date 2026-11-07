package com.qrsg.app.domain.analyzer

import java.util.Locale

/** Deterministic, offline heuristics. No URL is opened or submitted to a server. */
internal object HeuristicRules {
    private const val LONG_URL_THRESHOLD = 200
    private const val SUBDOMAIN_LABEL_THRESHOLD = 5
    private val shorteners = setOf(
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rb.gy",
    )
    private val keywords = Regex(
        "(?:^|[/?.&=_-])(?:login|signin|verify|verification|password|wallet|account|secure|update-payment)(?=$|[/?.&=_-])",
        RegexOption.IGNORE_CASE,
    )
    private val doubleEncoding = Regex("%25[0-9a-fA-F]{2}")
    private val dottedIpv4 = Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")
    private val numericHost = Regex("(?i)(?:0x[0-9a-f]+|[0-9]+|(?:[0-9]+\\.)+[0-9]+)")

    fun check(url: UrlParser.ParseResult.WebUrl): List<HeuristicFinding> = buildList {
        fun flag(id: HeuristicRuleId, severity: FindingSeverity, explanation: String) {
            add(HeuristicFinding(id, severity, explanation))
        }
        val uri = url.uri
        val scheme = uri.scheme.lowercase(Locale.ROOT)
        val host = url.host
        if (scheme == "http") flag(
            HeuristicRuleId.HTTP_SCHEME, FindingSeverity.MEDIUM,
            "This URL uses HTTP without HTTPS transport protection.",
        )
        if (url.hasUserInfo) flag(
            HeuristicRuleId.USER_INFO, FindingSeverity.HIGH,
            "The URL contains user-info or @ before the hostname; verify the actual domain.",
        )
        if (host.split('.').any { it.startsWith("xn--") }) flag(
            HeuristicRuleId.PUNYCODE_HOST, FindingSeverity.MEDIUM,
            "The hostname uses Punycode (xn--); check for visually similar characters.",
        )
        if (url.unicodeHost) flag(
            HeuristicRuleId.UNICODE_HOST, FindingSeverity.MEDIUM,
            "The hostname contains Unicode characters; inspect the domain carefully.",
        )
        val ipv4 = parseIpv4(host)
        val ipv6 = host.startsWith('[') && host.endsWith(']')
        if (ipv4 != null) flag(
            HeuristicRuleId.IPV4_HOST, FindingSeverity.MEDIUM,
            "The URL uses an IPv4 address rather than a domain name.",
        )
        if (ipv6) flag(
            HeuristicRuleId.IPV6_HOST, FindingSeverity.MEDIUM,
            "The URL uses an IPv6 address rather than a domain name.",
        )
        if (isNonPublic(host, ipv4, ipv6)) flag(
            HeuristicRuleId.NON_PUBLIC_DESTINATION, FindingSeverity.HIGH,
            "The destination is local, private, or reserved; inspect it carefully.",
        )
        if (numericHost.matches(host) && ipv4 == null) flag(
            HeuristicRuleId.NUMERIC_HOST, FindingSeverity.HIGH,
            "An unusual numeric hostname may disguise an IP address.",
        )
        if (host.matches(Regex("(?:[0-9]+\\.){3}[0-9]+")) &&
            host.split('.').any { it.length > 1 && it.startsWith('0') }) flag(
            HeuristicRuleId.LEADING_ZERO_IPV4, FindingSeverity.HIGH,
            "The IPv4 address contains leading zeros, which can be interpreted differently.",
        )
        if (host in shorteners || host.removePrefix("www.") in shorteners) flag(
            HeuristicRuleId.SHORTENER, FindingSeverity.MEDIUM,
            "A URL shortener conceals the final destination.",
        )
        if (!ipv6 && ipv4 == null && host.split('.').size >= SUBDOMAIN_LABEL_THRESHOLD) flag(
            HeuristicRuleId.MANY_SUBDOMAINS, FindingSeverity.LOW,
            "The hostname contains an unusual number of subdomain levels.",
        )
        if (url.source.length > LONG_URL_THRESHOLD) flag(
            HeuristicRuleId.LONG_URL, FindingSeverity.LOW,
            "The URL is unusually long.",
        )
        val pathAndQuery = "${uri.path.orEmpty()}?${uri.query.orEmpty()}"
        if (keywords.containsMatchIn(pathAndQuery)) flag(
            HeuristicRuleId.SENSITIVE_KEYWORD, FindingSeverity.LOW,
            "The path or query contains login or account-verification terms.",
        )
        if (doubleEncoding.containsMatchIn(url.source)) flag(
            HeuristicRuleId.DOUBLE_ENCODING, FindingSeverity.MEDIUM,
            "The URL contains apparent double percent-encoding.",
        )
        if (url.port != -1 && url.port != if (scheme == "https") 443 else 80) flag(
            HeuristicRuleId.NON_STANDARD_PORT, FindingSeverity.LOW,
            "The URL uses a non-standard port.",
        )
    }

    private fun parseIpv4(host: String): List<Int>? {
        if (!dottedIpv4.matches(host)) return null
        val octets = host.split('.').map { it.toInt() }
        return octets.takeIf { it.all { segment -> segment in 0..255 } }
    }

    private fun isNonPublic(host: String, ip: List<Int>?, ipv6: Boolean): Boolean {
        if (host == "localhost" || host.endsWith(".localhost") || host.endsWith(".local") ||
            host.endsWith(".internal") || host.endsWith(".test") || host.endsWith(".invalid")) return true
        if (ip != null) {
            val (a, b) = ip
            return a == 0 || a == 10 || a == 127 || (a == 169 && b == 254) ||
                (a == 172 && b in 16..31) || (a == 192 && b == 168) ||
                (a == 192 && b == 0 && (ip[2] == 0 || ip[2] == 2)) ||
                (a == 198 && (b == 18 || b == 19 || (b == 51 && ip[2] == 100))) ||
                (a == 203 && b == 0 && ip[2] == 113) ||
                (a == 100 && b in 64..127) || a >= 224
        }
        if (ipv6) {
            val literal = host.substring(1, host.length - 1).lowercase(Locale.ROOT)
            if (literal == "::" || literal == "::1" || literal.startsWith("fc") || literal.startsWith("fd") ||
                literal.startsWith("ff") || literal.startsWith("2001:db8:")) return true
            // fe80::/10 includes fe80:: through febf:: (not only fe80::/16).
            val firstGroup = literal.substringBefore(':').toIntOrNull(16)
            if (firstGroup != null && firstGroup in 0xfe80..0xfebf) return true
            // Common IPv4-mapped IPv6 form: ::ffff:127.0.0.1
            if (literal.startsWith("::ffff:")) {
                val suffix = literal.removePrefix("::ffff:")
                val dotted = parseIpv4(suffix)
                if (dotted != null) return isNonPublic("", dotted, false)
                // IPv4-mapped forms may use two hexadecimal groups instead of dotted IPv4.
                val parts = suffix.split(':')
                if (parts.size == 2 && parts.all { it.length in 1..4 }) {
                    val hi = parts[0].toIntOrNull(16)
                    val lo = parts[1].toIntOrNull(16)
                    if (hi != null && lo != null) {
                        return isNonPublic("", listOf(hi shr 8, hi and 255, lo shr 8, lo and 255), false)
                    }
                }
            }
        }
        return false
    }
}
