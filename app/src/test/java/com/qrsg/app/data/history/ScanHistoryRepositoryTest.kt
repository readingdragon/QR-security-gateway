package com.qrsg.app.data.history

import com.qrsg.app.domain.analyzer.RiskLevel
import com.qrsg.app.domain.analyzer.UrlAnalysisResult
import com.qrsg.app.domain.reputation.ReputationResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class ScanHistoryRepositoryTest {
    private class FakeDao : ScanDao {
        val rows = linkedMapOf<String, ScanRecord>()
        val flow = MutableStateFlow<List<ScanRecord>>(emptyList())
        override fun observeAll(): Flow<List<ScanRecord>> = flow
        override suspend fun findById(id: String) = rows[id]
        override suspend fun upsert(record: ScanRecord) {
            rows[record.id] = record
            flow.value = rows.values.toList()
        }
        override suspend fun delete(id: String) {
            rows.remove(id)
            flow.value = rows.values.toList()
        }
        override suspend fun deleteAll() {
            rows.clear()
            flow.value = emptyList()
        }
    }

    private val local = UrlAnalysisResult(RiskLevel.LOW_RISK, "clean", emptyList(), true)

    @Test fun onlineCheckUpdatesSameRowWithoutDuplicating() = runTest {
        val dao = FakeDao()
        val repo = ScanHistoryRepository(dao)
        repo.saveSnapshot("scan", 100L, local, null)
        repo.saveSnapshot("scan", 100L, local, ReputationResult.NoKnownThreat(200L))
        assertEquals(1, dao.rows.size)
        assertEquals("LOW_RISK", dao.rows.getValue("scan").finalRisk)
    }

    @Test fun delayedLocalResultCannotOverwriteKnownThreat() = runTest {
        val dao = FakeDao()
        val repo = ScanHistoryRepository(dao)
        repo.saveSnapshot("scan", 100L, local,
            ReputationResult.KnownThreat(setOf("MALWARE"), 200L))
        repo.saveSnapshot("scan", 100L, local, null)
        assertEquals("HIGH_RISK", dao.rows.getValue("scan").finalRisk)
        assertEquals("MALWARE", dao.rows.getValue("scan").threatTypes)
    }

    @Test fun deletingOneRecordPreservesOthers() = runTest {
        val dao = FakeDao()
        val repo = ScanHistoryRepository(dao)
        repo.saveSnapshot("1", 1L, local, null)
        repo.saveSnapshot("2", 2L, local, null)
        repo.delete("1")
        assertEquals(setOf("2"), dao.rows.keys)
    }

    @Test fun clearingHistoryRemovesEverything() = runTest {
        val dao = FakeDao()
        val repo = ScanHistoryRepository(dao)
        repo.saveSnapshot("1", 1L, local, null)
        repo.deleteAll()
        assertTrue(dao.rows.isEmpty())
    }
}
