package com.qrsg.app.data.history

import android.content.Context
import com.qrsg.app.domain.analyzer.UrlAnalysisResult
import com.qrsg.app.domain.reputation.ReputationResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** One record per scan. A delayed local-only update cannot erase online evidence. */
class ScanHistoryRepository internal constructor(private val dao: ScanDao) {
    private val mutex = Mutex()
    val records: Flow<List<ScanRecord>> = dao.observeAll()

    suspend fun saveSnapshot(
        id: String,
        scannedAtMs: Long,
        local: UrlAnalysisResult,
        online: ReputationResult?,
    ) = mutex.withLock {
        val existing = dao.findById(id)
        if (online == null && existing != null && existing.onlineStatus != "NOT_CHECKED") {
            return@withLock
        }
        dao.upsert(ScanRecordMapper.fromAssessment(id, scannedAtMs, local, online))
    }

    suspend fun delete(id: String) = mutex.withLock { dao.delete(id) }
    suspend fun deleteAll() = mutex.withLock { dao.deleteAll() }

    companion object {
        @Volatile private var instance: ScanHistoryRepository? = null
        fun get(context: Context): ScanHistoryRepository = instance ?: synchronized(this) {
            instance ?: ScanHistoryRepository(ScanHistoryDatabase.get(context).scanDao())
                .also { instance = it }
        }
    }
}
