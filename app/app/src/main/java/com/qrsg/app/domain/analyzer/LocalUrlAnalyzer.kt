package com.qrsg.app.domain.analyzer

/** Level 1 only. Never navigates, resolves DNS, redirects, or calls reputation APIs. */
object LocalUrlAnalyzer {
    fun analyze(rawValue: String): UrlAnalysisResult = when (val parsed = UrlParser.parse(rawValue)) {
        is UrlParser.ParseResult.Unsupported -> UrlAnalysisResult(
            riskLevel = RiskLevel.UNVERIFIED,
            title = "The web address could not be verified",
            reasons = listOf(parsed.message),
            isWebUrl = false,
        )
        is UrlParser.ParseResult.WebUrl -> {
            val findings = HeuristicRules.check(parsed)
            val riskLevel = if (findings.isEmpty()) RiskLevel.LOW_RISK else RiskLevel.SUSPICIOUS
            UrlAnalysisResult(
                riskLevel = riskLevel,
                title = if (findings.isEmpty())
                    "No obvious local risk indicators were found"
                else "Potential risk indicators were detected",
                reasons = if (findings.isEmpty())
                    listOf("Local analysis does not guarantee safety; URL reputation has not been checked.")
                else findings.map { it.description },
                isWebUrl = true,
                host = parsed.host,
                findings = findings,
            )
        }
    }
}
