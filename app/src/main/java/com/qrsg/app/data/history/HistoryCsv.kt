package com.qrsg.app.data.history

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/** No raw QR payload, URL, hostname, path, or query is exported. */
object HistoryCsv {
    private val utc = DateTimeFormatter.ISO_OFFSET_DATE_TIME.withZone(ZoneOffset.UTC)
    private val header = listOf(
        "scan_id", "timestamp_utc", "local_risk", "online_status",
        "final_risk", "heuristic_rule_ids", "threat_types",
    )

    fun encode(records: List<ScanRecord>): String = buildString {
        appendLine(header.joinToString(","))
        records.forEach { r ->
            val values = listOf(
                r.id, utc.format(Instant.ofEpochMilli(r.scannedAtMs)),
                r.localRisk, r.onlineStatus, r.finalRisk, r.findingIds, r.threatTypes,
            )
            appendLine(values.joinToString(",") { csvCell(it) })
        }
    }

    private fun csvCell(input: String): String {
        val potentiallyExecutable = input.trimStart().firstOrNull() in setOf('=', '+', '-', '@')
        val escaped = (if (potentiallyExecutable) "'$input" else input).replace("\"", "\"\"")
        return "\"$escaped\""
    }
}
