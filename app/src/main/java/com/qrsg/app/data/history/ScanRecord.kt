package com.qrsg.app.data.history

import androidx.room.Entity
import androidx.room.PrimaryKey

/** Intentionally excludes raw QR payload, URL, host, query, path and user text. */
@Entity(tableName = "scan_records")
data class ScanRecord(
    @PrimaryKey val id: String,
    val scannedAtMs: Long,
    val localRisk: String,
    val onlineStatus: String,
    val finalRisk: String,
    val findingIds: String,
    val threatTypes: String,
)
