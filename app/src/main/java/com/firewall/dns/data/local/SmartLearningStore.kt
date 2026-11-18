package com.firewall.dns.data.local

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.util.AtomicFile
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException

data class DomainObservationEvent(
    val domain: String,
    val blocked: Boolean,
    val observedAt: Long,
    val generation: Long = 0L,
    val firstObservedAt: Long = observedAt,
    val allowedCountDelta: Long = if (blocked) 0L else 1L,
    val blockedCountDelta: Long = if (blocked) 1L else 0L
)

data class DomainObservationSummary(
    val domain: String,
    val allowedCount: Long,
    val blockedCount: Long,
    val firstSeen: Long,
    val lastSeen: Long,
    val lastBlocked: Boolean
)

object DomainObservationPolicy {
    private val LABEL = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

    fun normalize(domain: String): String? {
        val clean = domain.trim().lowercase().trimEnd('.')
        if (clean.isEmpty() || clean.length > 253 || clean.contains("..")) return null
        val labels = clean.split('.')
        if (labels.size < 2 || labels.any { !LABEL.matches(it) }) return null
        return clean
    }

    fun isValidSummary(
        domain: String,
        allowedCount: Long,
        blockedCount: Long,
        firstSeen: Long,
        lastSeen: Long
    ): Boolean = normalize(domain) == domain &&
        allowedCount >= 0L && blockedCount >= 0L &&
        firstSeen >= 0L && lastSeen >= firstSeen
}

/**
 * Bounded aggregate learning stored as a versioned local JSON snapshot.
 * DNS decisions update only the in-memory map; AtomicFile persistence runs on the IO worker.
 * A one-time read-only migration preserves the previous SQLite aggregates when possible.
 */
class SmartLearningStore(context: Context) {
    companion object {
        private const val FILE_NAME = "firewalldns_learning.json"
        private const val LEGACY_DATABASE_NAME = "firewalldns_learning.db"
        private const val SCHEMA_VERSION = 1
        private const val MAX_DOMAINS = 5_000
    }

    private val appContext = context.applicationContext
    private val atomicFile = AtomicFile(File(appContext.filesDir, FILE_NAME))
    private val observations = LinkedHashMap<String, DomainObservationSummary>()
    private var dirty = false

    @Synchronized
    fun load() {
        if ((atomicFile.baseFile.exists() || File(atomicFile.baseFile.path + ".bak").exists()) &&
            readFileSnapshot()
        ) {
            appContext.deleteDatabase(LEGACY_DATABASE_NAME)
            return
        }

        val migrated = readLegacyDatabase() ?: return
        observations.clear()
        migrated.forEach { observations[it.domain] = it }
        dirty = true
        // Even an empty legacy database gets a committed versioned snapshot before deletion.
        flush()
    }

    @Synchronized
    fun recordBatch(events: List<DomainObservationEvent>) {
        if (events.isEmpty()) return
        events.forEach { event ->
            val domain = DomainObservationPolicy.normalize(event.domain) ?: return@forEach
            val timestamp = event.observedAt.coerceAtLeast(0L)
            val old = observations[domain]
            observations[domain] = DomainObservationSummary(
                domain = domain,
                allowedCount = addCounter(old?.allowedCount ?: 0L, event.allowedCountDelta),
                blockedCount = addCounter(old?.blockedCount ?: 0L, event.blockedCountDelta),
                firstSeen = minOf(old?.firstSeen ?: event.firstObservedAt, event.firstObservedAt),
                lastSeen = maxOf(old?.lastSeen ?: 0L, timestamp),
                lastBlocked = event.blocked
            )
        }
        if (observations.size > MAX_DOMAINS) {
            observations.values
                .sortedBy { it.lastSeen }
                .take(observations.size - MAX_DOMAINS)
                .forEach { observations.remove(it.domain) }
        }
        dirty = true
    }

    private fun addCounter(value: Long, increment: Long): Long =
        if (increment <= 0L || Long.MAX_VALUE - value < increment) {
            if (increment <= 0L) value else Long.MAX_VALUE
        } else {
            value + increment
        }

    @Synchronized
    fun getSnapshot(): List<DomainObservationSummary> =
        observations.values.sortedByDescending { it.lastSeen }

    @Synchronized
    fun flush() {
        if (!dirty) return
        val root = JSONObject().put("version", SCHEMA_VERSION)
        val rows = JSONArray()
        observations.values.forEach { item ->
            rows.put(
                JSONObject()
                    .put("domain", item.domain)
                    .put("allowed", item.allowedCount)
                    .put("blocked", item.blockedCount)
                    .put("firstSeen", item.firstSeen)
                    .put("lastSeen", item.lastSeen)
                    .put("lastBlocked", item.lastBlocked)
            )
        }
        root.put("domains", rows)

        var stream: java.io.FileOutputStream? = null
        try {
            stream = atomicFile.startWrite()
            stream.write(root.toString().toByteArray(Charsets.UTF_8))
            stream.fd.sync()
            atomicFile.finishWrite(stream)
            dirty = false
            appContext.deleteDatabase(LEGACY_DATABASE_NAME)
        } catch (error: Exception) {
            stream?.let { atomicFile.failWrite(it) }
            throw error
        }
    }

    @Synchronized
    fun clear() {
        observations.clear()
        dirty = true
        flush()
    }

    private fun readFileSnapshot(): Boolean {
        val parsed = try {
            atomicFile.openRead().bufferedReader(Charsets.UTF_8).use { JSONObject(it.readText()) }
        } catch (_: FileNotFoundException) {
            return false
        } catch (_: Exception) {
            return false
        }

        if (parsed.optInt("version", -1) != SCHEMA_VERSION) return false
        val rows = parsed.optJSONArray("domains") ?: return false
        if (rows.length() > MAX_DOMAINS) return false
        val restored = LinkedHashMap<String, DomainObservationSummary>()
        for (index in 0 until rows.length()) {
            val row = rows.optJSONObject(index) ?: return false
            if (!row.has("domain") || !row.has("allowed") || !row.has("blocked") ||
                !row.has("firstSeen") || !row.has("lastSeen") || !row.has("lastBlocked")
            ) return false
            val domainValue = row.opt("domain")
            val allowedValue = row.opt("allowed")
            val blockedValue = row.opt("blocked")
            val firstSeenValue = row.opt("firstSeen")
            val lastSeenValue = row.opt("lastSeen")
            val lastBlockedValue = row.opt("lastBlocked")
            if (domainValue !is String || allowedValue !is Number || blockedValue !is Number ||
                firstSeenValue !is Number || lastSeenValue !is Number || lastBlockedValue !is Boolean
            ) return false
            val domain = DomainObservationPolicy.normalize(domainValue) ?: return false
            val allowed = allowedValue.toLong()
            val blocked = blockedValue.toLong()
            val firstSeen = firstSeenValue.toLong()
            val lastSeen = lastSeenValue.toLong()
            if (!DomainObservationPolicy.isValidSummary(domain, allowed, blocked, firstSeen, lastSeen) ||
                restored.containsKey(domain)
            ) return false
            restored[domain] = DomainObservationSummary(
                domain, allowed, blocked, firstSeen, lastSeen, lastBlockedValue
            )
        }
        observations.clear()
        restored.values.sortedByDescending { it.lastSeen }.take(MAX_DOMAINS)
            .forEach { observations[it.domain] = it }
        dirty = false
        return true
    }

    private fun readLegacyDatabase(): List<DomainObservationSummary>? {
        val databaseFile = appContext.getDatabasePath(LEGACY_DATABASE_NAME)
        if (!databaseFile.exists()) return null
        return try {
            SQLiteDatabase.openDatabase(
                databaseFile.absolutePath, null, SQLiteDatabase.OPEN_READONLY
            ).use { db ->
                db.rawQuery(
                    "SELECT domain, allowed_count, blocked_count, first_seen, last_seen, last_blocked FROM domain_observations ORDER BY last_seen DESC LIMIT $MAX_DOMAINS",
                    null
                ).use { cursor ->
                    buildList {
                        while (cursor.moveToNext()) {
                            val domain = DomainObservationPolicy.normalize(cursor.getString(0)) ?: continue
                            add(
                                DomainObservationSummary(
                                    domain = domain,
                                    allowedCount = cursor.getLong(1).coerceAtLeast(0L),
                                    blockedCount = cursor.getLong(2).coerceAtLeast(0L),
                                    firstSeen = cursor.getLong(3).coerceAtLeast(0L),
                                    lastSeen = cursor.getLong(4).coerceAtLeast(0L),
                                    lastBlocked = cursor.getInt(5) != 0
                                )
                            )
                        }
                    }
                }
            }
        } catch (_: Exception) {
            null
        }
    }
}
