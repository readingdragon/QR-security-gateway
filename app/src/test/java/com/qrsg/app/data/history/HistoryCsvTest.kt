package com.qrsg.app.data.history

import org.junit.Assert.*
import org.junit.Test

class HistoryCsvTest {
    private val record = ScanRecord(
        "id-1", 0L, "LOW_RISK", "NO_KNOWN_THREAT", "LOW_RISK", "", ""
    )

    @Test fun emptyExportHasHeader() {
        assertTrue(HistoryCsv.encode(emptyList()).startsWith("scan_id,timestamp_utc"))
    }

    @Test fun csvIsUtcAndDoesNotContainUrl() {
        val result = HistoryCsv.encode(listOf(record))
        assertTrue(result.contains("1970-01-01T00:00:00Z"))
        assertTrue(result.contains("NO_KNOWN_THREAT"))
        assertFalse(result.contains("http://"))
    }

    @Test fun spreadsheetFormulaInjectionIsNeutralized() {
        val result = HistoryCsv.encode(listOf(record.copy(id = "=2+2")))
        assertTrue(result.contains("\"'=2+2\""))
    }

    @Test fun quotesAndNewlinesAreEscaped() {
        val result = HistoryCsv.encode(listOf(record.copy(id = "ab\"c\ndef")))
        assertTrue(result.contains("\"ab\"\"c\ndef\""))
    }
}
