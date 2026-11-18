package com.qrsg.app.ui.history

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.qrsg.app.data.history.HistoryCsv
import com.qrsg.app.data.history.ScanHistoryRepository
import com.qrsg.app.data.history.ScanRecord
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Composable
fun ScanHistoryScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val repository = remember(context) { ScanHistoryRepository.get(context) }
    val scans by repository.records.collectAsState(initial = emptyList())
    val scope = rememberCoroutineScope()
    var riskFilter by remember { mutableStateOf("ALL") }
    var dateFilter by remember { mutableStateOf("ALL") }
    var pendingDeleteId by remember { mutableStateOf<String?>(null) }
    var confirmClear by remember { mutableStateOf(false) }
    var feedback by remember { mutableStateOf<String?>(null) }
    var exportSnapshot by remember { mutableStateOf<List<ScanRecord>>(emptyList()) }

    val createCsv = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/csv")
    ) { uri ->
        if (uri != null) {
            val selected = exportSnapshot
            scope.launch {
                feedback = withContext(Dispatchers.IO) {
                    try {
                        val output = context.contentResolver.openOutputStream(uri)
                            ?: error("Unable to open export destination")
                        output.bufferedWriter(Charsets.UTF_8).use {
                            it.write(HistoryCsv.encode(selected))
                        }
                        "CSV exported (${selected.size} scans)."
                    } catch (_: Exception) {
                        "CSV export failed. Please choose another destination."
                    }
                }
            }
        }
    }

    val now = System.currentTimeMillis()
    val after = when (dateFilter) {
        "7D" -> now - 7L * 24 * 60 * 60 * 1000
        "30D" -> now - 30L * 24 * 60 * 60 * 1000
        else -> 0L
    }
    val displayed = scans.filter { r ->
        (riskFilter == "ALL" || r.finalRisk == riskFilter) && r.scannedAtMs >= after
    }
    val dangerCount = scans.count { it.finalRisk == "HIGH_RISK" }
    val suspiciousCount = scans.count { it.finalRisk == "SUSPICIOUS" }
    val lowCount = scans.count { it.finalRisk == "LOW_RISK" }
    val unknownCount = scans.count { it.finalRisk == "UNVERIFIED" }

    Column(modifier = modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Scan history", style = MaterialTheme.typography.headlineSmall)
            TextButton(onClick = onBack) { Text("Back") }
        }
        Text(
            "Local-only metadata. QR contents and full URLs are never saved.",
            style = MaterialTheme.typography.bodySmall
        )
        Text("Analytics · ${scans.size} total scans", style = MaterialTheme.typography.titleMedium)
        RiskBar("High risk", dangerCount, scans.size)
        RiskBar("Suspicious", suspiciousCount, scans.size)
        RiskBar("Low risk", lowCount, scans.size)
        RiskBar("Unverified", unknownCount, scans.size)
        Text("Known threats: ${scans.count { it.onlineStatus == "KNOWN_THREAT" }} · " +
            "Online checked: ${scans.count { it.onlineStatus == "KNOWN_THREAT" || it.onlineStatus == "NO_KNOWN_THREAT" }}",
            style = MaterialTheme.typography.bodySmall)

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(enabled = scans.isNotEmpty(), onClick = {
                exportSnapshot = scans.toList()
                createCsv.launch("qrsg-history.csv")
            }) { Text("Export CSV") }
            OutlinedButton(enabled = scans.isNotEmpty(), onClick = { confirmClear = true }) {
                Text("Clear history")
            }
        }
        feedback?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        HorizontalDivider()
        Text("Filter by risk", style = MaterialTheme.typography.titleSmall)
        Row(modifier = Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf("ALL", "HIGH_RISK", "SUSPICIOUS", "LOW_RISK", "UNVERIFIED").forEach { risk ->
                FilterChip(
                    selected = riskFilter == risk,
                    onClick = { riskFilter = risk },
                    label = { Text(risk.replace('_', ' ')) }
                )
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf("ALL", "7D", "30D").forEach { filter ->
                FilterChip(
                    selected = dateFilter == filter,
                    onClick = { dateFilter = filter },
                    label = { Text(when (filter) { "7D" -> "7 days"; "30D" -> "30 days"; else -> "All dates" }) }
                )
            }
        }
        Text("${displayed.size} matching records", style = MaterialTheme.typography.bodySmall)
        LazyColumn(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(displayed, key = { it.id }) { record ->
                ScanHistoryCard(record) { pendingDeleteId = record.id }
            }
        }
    }

    if (pendingDeleteId != null) {
        val id = pendingDeleteId!!
        AlertDialog(
            onDismissRequest = { pendingDeleteId = null },
            title = { Text("Delete this scan?") },
            text = { Text("Only the local history entry will be deleted.") },
            confirmButton = { TextButton(onClick = {
                pendingDeleteId = null
                scope.launch { repository.delete(id) }
            }) { Text("Delete") } },
            dismissButton = { TextButton(onClick = { pendingDeleteId = null }) { Text("Cancel") } }
        )
    }
    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text("Clear all scan history?") },
            text = { Text("This permanently deletes locally stored scan metadata.") },
            confirmButton = { TextButton(onClick = {
                confirmClear = false
                scope.launch { repository.deleteAll() }
            }) { Text("Clear all") } },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text("Cancel") } }
        )
    }
}

@Composable
private fun RiskBar(label: String, count: Int, total: Int) {
    val fraction = if (total > 0) count.toFloat() / total else 0f
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodySmall)
        Text("$count / $total", style = MaterialTheme.typography.bodySmall)
    }
    LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
}

@Composable
private fun ScanHistoryCard(record: ScanRecord, onDelete: () -> Unit) {
    val dateText = remember(record.scannedAtMs) {
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .withZone(ZoneId.systemDefault())
            .format(Instant.ofEpochMilli(record.scannedAtMs))
    }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(dateText, style = MaterialTheme.typography.labelMedium)
            Text("Final: ${record.finalRisk.replace('_', ' ')}", style = MaterialTheme.typography.titleMedium)
            Text("Local: ${record.localRisk} · Online: ${record.onlineStatus}",
                style = MaterialTheme.typography.bodySmall)
            if (record.findingIds.isNotBlank()) {
                Text("Rules: ${record.findingIds.replace('|', ',')}", style = MaterialTheme.typography.bodySmall)
            }
            if (record.threatTypes.isNotBlank()) {
                Text("Threats: ${record.threatTypes.replace('|', ',')}", style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = onDelete) { Text("Delete entry") }
        }
    }
}
