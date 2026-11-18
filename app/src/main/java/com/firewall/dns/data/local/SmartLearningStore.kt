package com.firewall.dns.data.local

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

data class DomainObservationEvent(
    val domain: String,
    val blocked: Boolean,
    val observedAt: Long
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
}

/**
 * Local, bounded aggregate memory. No app identifiers, query payloads, or raw event timeline
 * are persisted. WAL and batched transactions keep disk work away from the DNS hot path.
 */
class SmartLearningStore(context: Context) : SQLiteOpenHelper(
    context.applicationContext,
    DATABASE_NAME,
    null,
    DATABASE_VERSION
) {
    companion object {
        private const val DATABASE_NAME = "firewalldns_learning.db"
        private const val DATABASE_VERSION = 1
        private const val TABLE = "domain_observations"
        private const val MAX_DOMAINS = 5_000
    }

    init {
        setWriteAheadLoggingEnabled(true)
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE $TABLE (
                domain TEXT PRIMARY KEY NOT NULL,
                allowed_count INTEGER NOT NULL DEFAULT 0,
                blocked_count INTEGER NOT NULL DEFAULT 0,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                last_blocked INTEGER NOT NULL DEFAULT 0
            )
            """.trimIndent()
        )
        db.execSQL("CREATE INDEX idx_domain_observations_last_seen ON $TABLE(last_seen)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // Las futuras versiones deben migrar esta tabla sin borrar el conocimiento existente.
    }

    fun recordBatch(events: List<DomainObservationEvent>) {
        if (events.isEmpty()) return
        val db = writableDatabase
        db.beginTransaction()
        try {
            events.forEach { event ->
                val domain = DomainObservationPolicy.normalize(event.domain) ?: return@forEach
                val timestamp = event.observedAt.coerceAtLeast(0L)
                val existing = db.query(
                    TABLE,
                    arrayOf("allowed_count", "blocked_count", "first_seen"),
                    "domain = ?",
                    arrayOf(domain),
                    null,
                    null,
                    null
                ).use { cursor ->
                    if (cursor.moveToFirst()) {
                        Triple(cursor.getLong(0), cursor.getLong(1), cursor.getLong(2))
                    } else null
                }
                val values = ContentValues().apply {
                    put("domain", domain)
                    put("allowed_count", (existing?.first ?: 0L) + if (event.blocked) 0L else 1L)
                    put("blocked_count", (existing?.second ?: 0L) + if (event.blocked) 1L else 0L)
                    put("first_seen", existing?.third ?: timestamp)
                    put("last_seen", timestamp)
                    put("last_blocked", if (event.blocked) 1 else 0)
                }
                db.insertWithOnConflict(TABLE, null, values, SQLiteDatabase.CONFLICT_REPLACE)
            }
            val count = db.rawQuery("SELECT COUNT(*) FROM $TABLE", null).use {
                if (it.moveToFirst()) it.getInt(0) else 0
            }
            val excess = count - MAX_DOMAINS
            if (excess > 0) {
                db.delete(
                    TABLE,
                    "domain IN (SELECT domain FROM $TABLE ORDER BY last_seen ASC LIMIT ?)",
                    arrayOf(excess.toString())
                )
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun getSnapshot(): List<DomainObservationSummary> {
        val result = ArrayList<DomainObservationSummary>()
        readableDatabase.query(
            TABLE,
            arrayOf("domain", "allowed_count", "blocked_count", "first_seen", "last_seen", "last_blocked"),
            null,
            null,
            null,
            null,
            "last_seen DESC",
            MAX_DOMAINS.toString()
        ).use { cursor ->
            while (cursor.moveToNext()) {
                result += DomainObservationSummary(
                    domain = cursor.getString(0),
                    allowedCount = cursor.getLong(1),
                    blockedCount = cursor.getLong(2),
                    firstSeen = cursor.getLong(3),
                    lastSeen = cursor.getLong(4),
                    lastBlocked = cursor.getInt(5) != 0
                )
            }
        }
        return result
    }

    fun clear() {
        writableDatabase.delete(TABLE, null, null)
    }
}
