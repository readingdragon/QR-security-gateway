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
            "HTTP is used without HTTPS protection.",
        )
        if (url.hasUserInfo) flag(
            HeuristicRuleId.USER_INFO, FindingSeverity.HIGH,
            "The URL contains user data or an @ symbol before the hostname; check the actual domain.",
        )
        if (host.split('.').any { it.startsWith("xn--") }) flag(
            HeuristicRuleId.PUNYCODE_HOST, FindingSeverity.MEDIUM,
            "The hostname uses Punycode (xn--): potential obfuscation via visually similar characters.",
        )
        if (url.unicodeHost) flag(
            HeuristicRuleId.UNICODE_HOST, FindingSeverity.MEDIUM,
            "The hostname contains Unicode characters; check the domain spelling.",
        )
        val ipv4 = parseIpv4(host)
        val ipv6 = host.startsWith('[') && host.endsWith(']')
        if (ipv4 != null) flag(
            HeuristicRuleId.IPV4_HOST, FindingSeverity.MEDIUM,
            "An IPv4 address is used in the URL instead of a domain.",
        )
        if (ipv6) flag(
            HeuristicRuleId.IPV6_HOST, FindingSeverity.MEDIUM,
            "An IPv6 address is used in the URL instead of a domain.",
        )
        if (isNonPublic(host, ipv4, ipv6)) flag(
            HeuristicRuleId.NON_PUBLIC_DESTINATION, FindingSeverity.HIGH,
            "The address points to a local, private, or service node.",
        )
        if (numericHost.matches(host) && ipv4 == null) flag(
            HeuristicRuleId.NUMERIC_HOST, FindingSeverity.HIGH,
            "A non-standard numerical representation of a hostname can mask an IP address.",
        )
        if (host.matches(Regex("(?:[0-9]+\\.){3}[0-9]+")) &&
            host.split('.').any { it.length > 1 && it.startsWith('0') }) flag(
            HeuristicRuleId.LEADING_ZERO_IPV4, FindingSeverity.HIGH,
            "The IPv4 address contains leading zeros, which can lead to different interpretations.",
        )
        if (host in shorteners || host.removePrefix("www.") in shorteners) flag(
            HeuristicRuleId.SHORTENER, FindingSeverity.MEDIUM,
            "The link is shortened; the final site is unknown without following it.",
        )
        if (!ipv6 && ipv4 == null && host.split('.').size >= SUBDOMAIN_LABEL_THRESHOLD) flag(
            HeuristicRuleId.MANY_SUBDOMAINS, FindingSeverity.LOW,
            "The hostname has an unusually large number of subdomain levels.",
        )
        if (url.source.length > LONG_URL_THRESHOLD) flag(
            HeuristicRuleId.LONG_URL, FindingSeverity.LOW,
            "The URL is unusually long.",
        )
        val pathAndQuery = "${uri.path.orEmpty()}?${uri.query.orEmpty()}"
        if (keywords.containsMatchIn(pathAndQuery)) flag(
            HeuristicRuleId.SENSITIVE_KEYWORD, FindingSeverity.LOW,
            "The URL contains words related to authorization or account verification.",
        )
        if (doubleEncoding.containsMatchIn(url.source)) flag(
            HeuristicRuleId.DOUBLE_ENCODING, FindingSeverity.MEDIUM,
            "The URL contains signs of double percent-encoding.",
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
                (a == 100 && b in 64..127) || a >= 224
        }
        if (ipv6) {
            val literal = host.substring(1, host.length - 1).lowercase(Locale.ROOT)
            if (literal == "::" || literal == "::1" || literal.startsWith("fc") || literal.startsWith("fd")) return true
            // fe80::/10 includes fe80:: through febf:: (not only fe80::/16).
            val firstGroup = literal.substringBefore(':').toIntOrNull(16)
            if (firstGroup != null && firstGroup in 0xfe80..0xfebf) return true
            // Common IPv4-mapped IPv6 form: ::ffff:127.0.0.1
            if (literal.startsWith("::ffff:")) {
                val mapped = parseIpv4(literal.removePrefix("::ffff:"))
                if (mapped != null) return isNonPublic("", mapped, false)
            }
        }
        return false
    }
}
