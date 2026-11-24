package com.qrsg.app.experiment

import com.qrsg.app.data.history.ScanRecordMapper
import com.qrsg.app.data.reputation.SafeBrowsingV5Provider
import com.qrsg.app.domain.analyzer.HeuristicRuleId
import com.qrsg.app.domain.analyzer.LocalUrlAnalyzer
import com.qrsg.app.domain.analyzer.UrlAnalysisResult
import com.qrsg.app.domain.reputation.ReputationResult
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.time.Instant
import java.util.Locale
import kotlin.random.Random

/**
 * Opt-in, host-JVM benchmark using the REAL QRSG production classes.
 * Never visits scanned URLs and does not execute CameraX/ML Kit/Android UI/Room DB.
 * Online mode transmits the URL (except fragment) to Google's Safe Browsing API
 * only after the user explicitly enables online mode in the wrapper script.
 *
 * This JUnit method is skipped during ordinary Gradle unit-test runs.
 */
class QrsgDatasetBenchmarkTest {
    private data class Case(
        val id: String, val label: String, val source: String,
        val hash: String, val url: String,
    )

    private val columns = listOf(
        "test_id", "ground_truth", "source", "url_sha256", "scan_id",
        "scanned_at_utc", "run_mode", "local_risk", "heuristic_rule_ids",
        "online_status", "threat_types", "online_attempted", "online_block_reason",
        "online_from_cache", "final_risk", "local_ms", "online_ms", "total_ms",
    )

    @Test
    fun runDatasetBenchmark() = runBlocking {
        val rawRoot = System.getenv("QRSG_BENCHMARK_ROOT")
        assumeTrue("Benchmark is opt-in via QRSG_BENCHMARK_ROOT", !rawRoot.isNullOrBlank())

        val root = Path.of(rawRoot!!).toAbsolutePath().normalize()
        val mode = System.getenv("QRSG_BENCHMARK_MODE") ?: "offline"
        require(mode == "offline" || mode == "online") { "Mode must be offline or online" }
        val onlineEnabled = mode == "online"
        val key = if (onlineEnabled) (System.getenv("QRSG_BENCHMARK_API_KEY")
            ?: System.getenv("QRSG_SAFE_BROWSING_API_KEY").orEmpty()) else ""
        require(!onlineEnabled || key.isNotBlank()) {
            "Online mode requires QRSG_BENCHMARK_API_KEY (or QRSG_SAFE_BROWSING_API_KEY)"
        }
        require(!onlineEnabled || System.getenv("QRSG_BENCHMARK_SEND_URLS") == "YES") {
            "Online mode requires explicit QRSG_BENCHMARK_SEND_URLS=YES consent"
        }

        val seed = (System.getenv("QRSG_BENCHMARK_SEED") ?: "42").toInt()
        val limit = (System.getenv("QRSG_BENCHMARK_LIMIT") ?: "0").toInt()
        val delayMs = (System.getenv("QRSG_BENCHMARK_DELAY_MS") ?: "1200").toLong()
        val retryUnavailable = System.getenv("QRSG_BENCHMARK_RETRY_UNAVAILABLE") == "YES"
        require(limit >= 0 && delayMs >= 0) { "Limit and delay must not be negative" }
        val output = Path.of(System.getenv("QRSG_BENCHMARK_OUTPUT")
            ?: root.resolve("results/$mode.csv").toString()).toAbsolutePath().normalize()
        Files.createDirectories(output.parent)
        val allCases = loadCases(root)
        require(allCases.isNotEmpty()) { "No records found" }
        val ids = allCases.associateBy { it.id }
        val existing = mutableSetOf<String>()

        if (Files.exists(output)) {
            val rows = csvRead(output)
            rows.forEach { row ->
                val id = row["test_id"].orEmpty()
                val expected = ids[id] ?: error("Existing result refers to an unknown test_id: $id")
                require(row["ground_truth"] == expected.label &&
                        row["url_sha256"] == expected.hash && row["run_mode"] == mode) {
                    "Existing output conflicts with input manifest or mode: $id. Use a different output file."
                }
                check(existing.add(id)) { "Duplicate record in existing results: $id" }
            }
            if (retryUnavailable && onlineEnabled) {
                val bad = rows.filter { it["online_status"].orEmpty().startsWith("UNAVAILABLE_") }
                if (bad.isNotEmpty()) {
                    val backup = output.resolveSibling(
                        output.fileName.toString() + ".before-retry-" + System.nanoTime() + ".bak")
                    Files.copy(output, backup)
                    val retained = rows.filterNot { it in bad }
                    Files.write(
                        output,
                        (listOf(csvLine(columns)) + retained.map { row ->
                            csvLine(columns.map { row[it].orEmpty() })
                        }).joinToString("\n", postfix = "\n")
                            .toByteArray(StandardCharsets.UTF_8),
                        StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.WRITE
                    )
                    existing.clear()
                    retained.forEach { existing.add(it["test_id"].orEmpty()) }
                    println("Removed ${bad.size} unavailable results for retry. Backup: $backup")
                }
            }
        } else {
            Files.write(
                output,
                (csvLine(columns) + "\n").toByteArray(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE_NEW
            )
        }

        // Stable, random order; --limit N can be raised on subsequent invocations.
        val shuffled = allCases.shuffled(Random(seed))
        val selected = if (limit == 0) shuffled else shuffled.take(limit)
        val provider = if (onlineEnabled) SafeBrowsingV5Provider(key) else null
        var newlyCompleted = 0
        var stopped = ""
        println("QRSG benchmark: ${selected.size} selected, ${existing.size} already recorded; mode=$mode")

        for (case in selected) {
            if (case.id in existing) continue
            val started = System.nanoTime()
            val scannedAt = Instant.now().toString()
            val local = LocalUrlAnalyzer.analyze(case.url)
            val localDone = System.nanoTime()

            val block = blockedOnlineReason(local)
            val onlineAttempted = onlineEnabled && block == null
            val online: ReputationResult? = if (onlineAttempted) provider!!.checkUrl(case.url) else null
            val onlineDone = System.nanoTime()
            // Use the SAME production mapper as the Android app (without writing to Room).
            val record = ScanRecordMapper.fromAssessment(
                id = case.id, scannedAtMs = System.currentTimeMillis(), local = local, online = online)
            val row = mapOf(
                "test_id" to case.id,
                "ground_truth" to case.label,
                "source" to case.source,
                "url_sha256" to case.hash,
                "scan_id" to record.id,
                "scanned_at_utc" to scannedAt,
                "run_mode" to mode,
                "local_risk" to record.localRisk,
                "heuristic_rule_ids" to record.findingIds,
                "online_status" to record.onlineStatus,
                "threat_types" to record.threatTypes,
                "online_attempted" to onlineAttempted.toString(),
                "online_block_reason" to if (onlineEnabled) (block ?: "") else "DISABLED",
                "online_from_cache" to when (online) {
                    is ReputationResult.KnownThreat -> online.fromCache.toString()
                    is ReputationResult.NoKnownThreat -> online.fromCache.toString()
                    else -> ""
                },
                "final_risk" to record.finalRisk,
                "local_ms" to ms(localDone - started),
                "online_ms" to if (onlineAttempted) ms(onlineDone - localDone) else "",
                "total_ms" to ms(onlineDone - started),
            )
            // Flush to disk after EACH record so Ctrl+C or a network failure doesn't lose work.
            Files.newBufferedWriter(output, StandardCharsets.UTF_8, StandardOpenOption.APPEND).use {
                it.write(csvLine(columns.map { name -> row[name].orEmpty() }))
                it.newLine()
            }
            newlyCompleted++
            if (newlyCompleted % 20 == 0 || newlyCompleted == selected.size) {
                println("Completed $newlyCompleted new cases, last=${case.id}, status=${record.onlineStatus}")
            }
            if (record.onlineStatus in setOf("UNAVAILABLE_RATE_LIMITED", "UNAVAILABLE_AUTHENTICATION")) {
                stopped = record.onlineStatus
                break // Don't send hundreds more requests after quota/authentication failures.
            }
            if (onlineAttempted && delayMs > 0) Thread.sleep(delayMs)
        }
        println("Wrote $newlyCompleted new records to $output")
        if (stopped.isNotEmpty()) {
            println("STOP: $stopped. Fix API/quota before retrying in a NEW output file.")
        }
    }

    /** Match restrictions in OnlineReputationSection (UI), not just provider internals. */
    private fun blockedOnlineReason(local: UrlAnalysisResult): String? {
        val ids = local.findings.map { it.id }.toSet()
        return when {
            !local.isWebUrl -> "NOT_A_WEB_URL"
            HeuristicRuleId.NON_PUBLIC_DESTINATION in ids -> "NON_PUBLIC_DESTINATION"
            HeuristicRuleId.USER_INFO in ids -> "URL_CONTAINS_USER_INFO"
            HeuristicRuleId.NUMERIC_HOST in ids || HeuristicRuleId.LEADING_ZERO_IPV4 in ids ->
                "AMBIGUOUS_NUMERIC_HOST"
            else -> null
        }
    }

    private fun loadCases(root: Path): List<Case> {
        val result = mutableListOf<Case>()
        val ids = mutableSetOf<String>()
        val hashes = mutableSetOf<String>()
        for (label in listOf("benign", "malicious")) {
            val path = root.resolve("$label/manifest.csv")
            for (row in csvRead(path)) {
                val id = row["test_id"].orEmpty().trim()
                val url = row["url"].orEmpty()
                val hash = row["url_sha256"].orEmpty().lowercase(Locale.ROOT)
                require(id.isNotEmpty() && row["ground_truth"]?.lowercase(Locale.ROOT) == label) {
                    "Invalid class or test_id in $path"
                }
                require(url.isNotBlank() && hash == sha256(url)) {
                    "URL/SHA256 mismatch: $id"
                }
                check(ids.add(id)) { "Duplicate test_id: $id" }
                check(hashes.add(hash)) { "Duplicate URL across manifests: $id" }
                result.add(Case(id, label, row["source"].orEmpty(), hash, url))
            }
        }
        return result
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun ms(nanoseconds: Long): String =
        String.format(Locale.ROOT, "%.3f", nanoseconds / 1_000_000.0)

    private fun csvLine(values: List<String>): String = values.joinToString(",") { raw ->
        // Also prevent spreadsheet formula injection if a dataset has a malicious "source" field.
        val escaped = if (raw.trimStart().firstOrNull() in setOf('=', '+', '-', '@')) "'$raw" else raw
        "\"" + escaped.replace("\"", "\"\"") + "\""
    }

    /** Minimal RFC-4180 CSV reader (commas, escaped quotes and embedded newlines). */
    private fun csvRead(path: Path): List<Map<String, String>> {
        require(Files.isRegularFile(path)) { "File not found: $path" }
        val raw = String(Files.readAllBytes(path), StandardCharsets.UTF_8)
    .removePrefix("\uFEFF")
        val rows = mutableListOf<List<String>>()
        val cells = mutableListOf<String>()
        val cell = StringBuilder()
        var quoted = false
        var i = 0
        fun field() { cells.add(cell.toString()); cell.setLength(0) }
        fun line() { field(); rows.add(cells.toList()); cells.clear() }
        while (i < raw.length) {
            val c = raw[i]
            if (quoted) {
                if (c == '"' && i + 1 < raw.length && raw[i + 1] == '"') {
                    cell.append('"'); i++
                } else if (c == '"') quoted = false
                else cell.append(c)
            } else {
                when (c) {
                    '"' -> {
                        require(cell.isEmpty()) { "Malformed CSV quote: $path" }
                        quoted = true
                    }
                    ',' -> field()
                    '\n' -> line()
                    '\r' -> {
                        line()
                        if (i + 1 < raw.length && raw[i + 1] == '\n') i++
                    }
                    else -> cell.append(c)
                }
            }
            i++
        }
        require(!quoted) { "Unclosed CSV quote: $path" }
        if (cell.isNotEmpty() || cells.isNotEmpty()) line()
        require(rows.isNotEmpty()) { "Empty CSV: $path" }
        val header = rows.first()
        require(header.size == header.toSet().size) { "Duplicate CSV headers: $path" }
        val required = setOf("test_id", "ground_truth", "url_sha256", "url")
        if (path.fileName.toString() == "manifest.csv") {
            require(header.toSet().containsAll(required)) { "Missing columns in $path" }
        } else {
            require(header.toSet().containsAll(columns)) { "Invalid existing results CSV: $path" }
        }
        return rows.drop(1).mapIndexed { index, fields ->
            require(fields.size == header.size) { "Bad CSV column count at row ${index + 2}: $path" }
            header.zip(fields).toMap()
        }
    }
}
