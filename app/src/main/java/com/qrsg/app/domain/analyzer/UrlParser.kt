package com.qrsg.app.domain.analyzer

import java.net.IDN
import java.net.URI
import java.net.URISyntaxException
import java.util.Locale

/** Strict, network-free web URL parser. It does NOT follow redirects or resolve DNS. */
internal object UrlParser {
    private const val MAX_INPUT_LENGTH = 8192

    sealed interface ParseResult {
        data class WebUrl(
            val source: String,
            val uri: URI,
            val host: String,
            val port: Int,
            val unicodeHost: Boolean,
            val hasUserInfo: Boolean,
        ) : ParseResult

        data class Unsupported(val message: String) : ParseResult
    }

    fun parse(raw: String): ParseResult {
        val input = raw.trim()
        if (input.isEmpty()) return unsupported("QR-код не містить тексту.")
        if (input.length > MAX_INPUT_LENGTH) return unsupported("Вміст надто довгий для локального аналізу URL.")
        if (input.any { it.isWhitespace() || Character.isISOControl(it) }) {
            return unsupported("URL contains whitespace or control characters.")
        }
        val uri = try { URI(input) } catch (_: URISyntaxException) {
            return unsupported("Invalid URL syntax.")
        }
        val scheme = uri.scheme?.lowercase(Locale.ROOT)
        if (scheme != "https" && scheme != "http") {
            return unsupported("Only full HTTP/HTTPS web addresses are supported; other types of QR content have not been tested.")
        }
        if (uri.isOpaque || uri.rawAuthority.isNullOrEmpty()) {
            return unsupported("URL does not contain a valid hostname.")
        }
        val authority = uri.rawAuthority
        if (authority.count { it == '@' } > 1) return unsupported("Invalid part of the URL containing the username.")

        val hostPort = if ('@' in authority) authority.substringAfterLast('@') else authority
        val unicodeHost = hostPort.any { it.code > 127 }
        val host: String
        val port: Int

        if (!unicodeHost) {
            // Java's URI parser validates the ASCII hostname and bracketed IPv6 literal.
            val javaHost = uri.host ?: return unsupported("URL contains an invalid hostname or port.")
            host = normalizeHost(javaHost) ?: return unsupported("URL contains an invalid hostname.")
            port = uri.port
            if (hostPort.endsWith(':')) return unsupported("URL port cannot be empty.")
        } else {
            // java.net.URI.host is null for many valid Unicode IDNs. Convert the
            // authority's hostname using IDN, then verify it with URI again.
            if (hostPort.startsWith('[')) return unsupported("Invalid IPv6 hostname.")
            val colonIndex = hostPort.lastIndexOf(':')
            val rawHost = if (colonIndex >= 0) hostPort.substring(0, colonIndex) else hostPort
            if (':' in rawHost) return unsupported("Invalid URL hostname.")
            host = normalizeHost(rawHost) ?: return unsupported("Invalid international domain name.")
            val portText = if (colonIndex >= 0) hostPort.substring(colonIndex + 1) else null
            port = when {
                portText == null -> -1
                portText.isEmpty() || !portText.all { it in '0'..'9' } -> return unsupported("Invalid URL port.")
                else -> portText.toIntOrNull() ?: return unsupported("Invalid URL port.")
            }
            val verified = try { URI("$scheme://$host${if (port >= 0) ":$port" else ""}/") }
            catch (_: URISyntaxException) { return unsupported("Invalid international domain name.") }
            if (verified.host == null) return unsupported("Invalid international domain name.")
        }
        if (port != -1 && port !in 1..65535) return unsupported("The URL port is out of the valid range.")
        // Avoid accepting ambiguous colon syntax on a host, for example "host:+80".
        if (!unicodeHost && hostPort.contains(':') && !hostPort.startsWith('[') && port == -1) {
            return unsupported("Invalid URL port.")
        }
        return ParseResult.WebUrl(
            source = input, uri = uri, host = host,
            port = port, unicodeHost = unicodeHost,
            hasUserInfo = uri.rawUserInfo != null || '@' in authority,
        )
    }

    private fun normalizeHost(rawHost: String): String? {
        val trimmed = rawHost.trimEnd('.')
        if (trimmed.isEmpty()) return null
        if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
            return trimmed.lowercase(Locale.ROOT) // URI already checked IPv6 grammar.
        }
        return try {
            val ascii = IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
            if (ascii.length > 253 || ascii.isEmpty() || ascii.split('.').any { it.isEmpty() || it.length > 63 }) null
            else ascii
        } catch (_: IllegalArgumentException) { null }
    }

    private fun unsupported(reason: String) = ParseResult.Unsupported(reason)
}
