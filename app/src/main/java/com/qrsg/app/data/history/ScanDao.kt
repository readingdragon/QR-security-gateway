package com.qrsg.app.data.history

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanDao {
    @Query("SELECT * FROM scan_records ORDER BY scannedAtMs DESC, id DESC")
    fun observeAll(): Flow<List<ScanRecord>>

    @Query("SELECT * FROM scan_records WHERE id = :id LIMIT 1")
    suspend fun findById(id: String): ScanRecord?

    @Upsert suspend fun upsert(record: ScanRecord)
    @Query("DELETE FROM scan_records WHERE id = :id") suspend fun delete(id: String)
    @Query("DELETE FROM scan_records") suspend fun deleteAll()
}
