package com.qrsg.app.domain.link

import org.junit.Assert.*
import org.junit.Test

class ReviewedWebLinkParserTest {
    @Test fun httpsAllowed() {
        val link = ReviewedWebLinkParser.parse("https://example.com/login?x=1")!!
        assertEquals("example.com", link.actualHost)
        assertEquals("https://example.com/login?x=1", link.originalUrl)
    }

    @Test fun httpAllowedEvenWhenLocallySuspicious() {
        assertNotNull(ReviewedWebLinkParser.parse("http://example.com/"))
    }

    @Test fun privateHostCanBeOpenedAfterConfirmation() {
        assertEquals("192.168.1.1", ReviewedWebLinkParser.parse("http://192.168.1.1/")?.actualHost)
    }

    @Test fun userInfoShowsRealDestination() {
        val link = ReviewedWebLinkParser.parse("https://trusted.example@untrusted.example/login")!!
        assertEquals("untrusted.example", link.actualHost)
        assertTrue(link.hasUserInfo)
    }

    @Test fun stripsSurroundingWhitespaceOnly() {
        val link = ReviewedWebLinkParser.parse("  https://example.com/a%2Fb#frag  ")!!
        assertEquals("https://example.com/a%2Fb#frag", link.originalUrl)
    }

    @Test fun javascriptIsRejected() = assertNull(ReviewedWebLinkParser.parse("javascript:alert(1)"))
    @Test fun intentIsRejected() = assertNull(ReviewedWebLinkParser.parse("intent://example.com/#Intent;end"))
    @Test fun fileIsRejected() = assertNull(ReviewedWebLinkParser.parse("file:///etc/passwd"))
    @Test fun wifiPayloadIsRejected() = assertNull(ReviewedWebLinkParser.parse("WIFI:T:WPA;S:x;P:y;;"))
    @Test fun malformedUrlIsRejected() = assertNull(ReviewedWebLinkParser.parse("https://example.com:99999/"))
}
