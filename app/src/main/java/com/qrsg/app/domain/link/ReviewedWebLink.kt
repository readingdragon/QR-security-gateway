package com.qrsg.app.domain.link

import com.qrsg.app.domain.analyzer.UrlParser

/**
 * Local gate for external navigation.
 * Never opens, resolves, follows redirects or submits a URL.
 */
data class ReviewedWebLink(
    val originalUrl: String,
    val actualHost: String,
    val hasUserInfo: Boolean,
)

object ReviewedWebLinkParser {
    fun parse(rawValue: String): ReviewedWebLink? = when (
        val parsed = UrlParser.parse(rawValue)
    ) {
        is UrlParser.ParseResult.WebUrl -> ReviewedWebLink(
            originalUrl = parsed.source,
            actualHost = parsed.host,
            hasUserInfo = parsed.hasUserInfo,
        )
        is UrlParser.ParseResult.Unsupported -> null
    }
}
