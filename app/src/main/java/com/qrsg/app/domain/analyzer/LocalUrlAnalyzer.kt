package com.qrsg.app.domain.analyzer

import android.net.Uri

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
            return unverified("QR-код не містить тексту.")
        }

        if (value.any { it.isWhitespace() }) {
            return unverified("Вміст містить пробіли й не схожий на коректний URL.")
        }

        val uri = try {
            Uri.parse(value)
        } catch (_: Exception) {
            return unverified("Не вдалося розібрати адресу.")
        }

        val scheme = uri.scheme?.lowercase()
        val host = uri.host?.lowercase()?.trimEnd('.')

        if (scheme !in setOf("http", "https") || host.isNullOrBlank()) {
            return unverified(
                "Це не повна вебадреса HTTP/HTTPS. Не відкривайте її, доки не перевірите вміст."
            )
        }

        val reasons = mutableListOf<String>()

        if (scheme == "http") {
            reasons += "З'єднання використовує HTTP без шифрування HTTPS."
        }

        if (uri.encodedAuthority?.contains('@') == true) {
            reasons += "Адреса містить символ @ в частині з доменом — перевірте справжній хост."
        }

        if (host.startsWith("xn--") || host.split('.').any { it.startsWith("xn--") }) {
            reasons += "Домен містить Punycode (xn--); перевірте, чи не маскується схожий символ."
        }

        if (IPV4.matches(host)) {
            reasons += "Замість звичайного доменного імені використано IPv4-адресу."
        }

        if (host in knownShorteners) {
            reasons += "Використано сервіс скорочення посилань; кінцевий сайт тут невідомий."
        }

        if (host.split('.').size >= 5) {
            reasons += "Домен має багато рівнів піддоменів."
        }

        if (value.length > 200) {
            reasons += "URL незвично довгий."
        }

        val pathAndQuery = "${uri.path.orEmpty()}?${uri.query.orEmpty()}"
            .lowercase()

        if (suspiciousWords.any { word -> pathAndQuery.contains(word) }) {
            reasons += "У шляху або параметрах є слова, які часто зустрічаються в запитах входу чи перевірки облікового запису."
        }

        return if (reasons.isEmpty()) {
            UrlAnalysisResult(
                riskLevel = RiskLevel.LOW_RISK,
                title = "Очевидних локальних ознак ризику не знайдено",
                reasons = listOf(
                    "Це не підтверджує безпечність сайту. Репутацію URL ще не перевірено."
                ),
                isWebUrl = true,
            )
        } else {
            UrlAnalysisResult(
                riskLevel = RiskLevel.SUSPICIOUS,
                title = "Виявлено ознаки, які варто перевірити",
                reasons = reasons,
                isWebUrl = true,
            )
        }
    }

    private fun unverified(reason: String) = UrlAnalysisResult(
        riskLevel = RiskLevel.UNVERIFIED,
        title = "Не вдалося підтвердити вебадресу",
        reasons = listOf(reason),
        isWebUrl = false,
    )

    private val IPV4 = Regex(
        """^(?:\d{1,3}\.){3}\d{1,3}$"""
    )
}