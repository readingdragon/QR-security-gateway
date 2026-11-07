package com.qrsg.app.domain.analyzer

/** Level 1 only. Never navigates, resolves DNS, redirects, or calls reputation APIs. */
object LocalUrlAnalyzer {
    fun analyze(rawValue: String): UrlAnalysisResult = when (val parsed = UrlParser.parse(rawValue)) {
        is UrlParser.ParseResult.Unsupported -> UrlAnalysisResult(
            riskLevel = RiskLevel.UNVERIFIED,
            title = "Web address not verified",
            reasons = listOf(parsed.message),
            isWebUrl = false,
        )
        is UrlParser.ParseResult.WebUrl -> {
            val findings = HeuristicRules.check(parsed)
            val riskLevel = if (findings.isEmpty()) RiskLevel.LOW_RISK else RiskLevel.SUSPICIOUS
            UrlAnalysisResult(
                riskLevel = riskLevel,
                title = if (findings.isEmpty())
                    "No obvious local signs of risk were found."
                else "Signs requiring attention have been detected.",
                reasons = if (findings.isEmpty())
                    listOf("Local analysis does not guarantee safety; the URL's reputation has not been verified.")
                else findings.map { it.description },
                isWebUrl = true,
                host = parsed.host,
                findings = findings,
            )
        }
    }
}
