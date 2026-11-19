package com.firewall.dns.data.local

import android.content.Context
import com.firewall.dns.domain.model.DnsLogEntry
import org.json.JSONArray
import org.json.JSONObject

data class ActivitySnapshot(
    val logs: List<DnsLogEntry>,
    val totalAllowed: Long,
    val totalBlocked: Long
)

class PreferencesDataSource(context: Context) {

    private val prefs = context.applicationContext
        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    companion object {
        private const val PREFS_NAME = "firewall_prefs"
        private const val KEY_CUSTOM_BLOCK = "custom_block"
        private const val KEY_CUSTOM_ALLOW = "custom_allow"
        private const val KEY_EXCLUDED_APPS = "excluded_apps"
        private const val KEY_BLOCKED_APPS = "blocked_apps"
        private const val KEY_SHOULD_RUN = "should_run"
        private const val KEY_BLOCKLIST_URLS = "blocklist_urls"
        private const val KEY_SMART_MODE = "smart_mode_enabled"
        private const val KEY_ADBLOCK_MIGRATED = "adblock_syntax_migrated_v1"
        private const val KEY_OBSERVATION_MODE = "observation_mode_enabled"
        private const val KEY_ACTIVITY_LOGS = "activity_logs_v1"
        private const val KEY_TOTAL_ALLOWED = "activity_total_allowed"
        private const val KEY_TOTAL_BLOCKED = "activity_total_blocked"

        const val DEFAULT_ADBLOCK_URL =
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt"
    }

    init {
        // Retira los datos de aprendizaje de versiones anteriores: ya no forman parte del producto.
        prefs.edit().remove("learned_tokens").apply()
        context.applicationContext.deleteFile("firewalldns_learning.json")
        context.applicationContext.deleteFile("firewalldns_learning.json.bak")
        context.applicationContext.deleteDatabase("firewalldns_learning.db")
        if (!prefs.getBoolean(KEY_ADBLOCK_MIGRATED, false)) {
            prefs.edit()
                .putString(KEY_BLOCKLIST_URLS, DEFAULT_ADBLOCK_URL)
                .putBoolean(KEY_ADBLOCK_MIGRATED, true)
                .apply()
        }
    }

    fun getCustomBlockSet(): Set<String> =
        prefs.getStringSet(KEY_CUSTOM_BLOCK, emptySet())?.toSet() ?: emptySet()

    fun saveCustomBlockSet(set: Set<String>) {
        prefs.edit().putStringSet(KEY_CUSTOM_BLOCK, set.toSet()).apply()
    }

    fun getCustomAllowSet(): Set<String> =
        prefs.getStringSet(KEY_CUSTOM_ALLOW, emptySet())?.toSet() ?: emptySet()

    fun saveCustomAllowSet(set: Set<String>) {
        prefs.edit().putStringSet(KEY_CUSTOM_ALLOW, set.toSet()).apply()
    }

    fun getExcludedPackages(): Set<String> =
        prefs.getStringSet(KEY_EXCLUDED_APPS, emptySet())?.toSet() ?: emptySet()

    fun saveExcludedPackages(set: Set<String>) {
        prefs.edit().putStringSet(KEY_EXCLUDED_APPS, set.toSet()).apply()
    }

    fun getBlockedApps(): Set<String> =
        prefs.getStringSet(KEY_BLOCKED_APPS, emptySet())?.toSet() ?: emptySet()

    fun saveBlockedApps(set: Set<String>) {
        prefs.edit().putStringSet(KEY_BLOCKED_APPS, set.toSet()).apply()
    }

    fun getShouldRun(): Boolean = prefs.getBoolean(KEY_SHOULD_RUN, false)

    fun saveShouldRun(shouldRun: Boolean) {
        prefs.edit().putBoolean(KEY_SHOULD_RUN, shouldRun).apply()
    }

    fun getBlocklistUrls(): List<String> {
        val raw = prefs.getString(KEY_BLOCKLIST_URLS, null)
        return if (raw == null) listOf(DEFAULT_ADBLOCK_URL)
        else raw.lines().map { it.trim() }.filter { it.startsWith("http") }
    }

    fun saveBlocklistUrls(urls: List<String>) {
        val sep = System.lineSeparator()
        prefs.edit().putString(KEY_BLOCKLIST_URLS, urls.joinToString(sep)).apply()
    }

    fun getSmartModeEnabled(): Boolean = prefs.getBoolean(KEY_SMART_MODE, true)

    fun saveSmartModeEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_SMART_MODE, enabled).apply()
    }

    fun getObservationModeEnabled(): Boolean =
        prefs.getBoolean(KEY_OBSERVATION_MODE, true)

    fun saveObservationModeEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_OBSERVATION_MODE, enabled).apply()
    }

    fun getActivitySnapshot(): ActivitySnapshot {
        val raw = prefs.getString(KEY_ACTIVITY_LOGS, null)
        val logs = if (raw.isNullOrBlank()) {
            emptyList()
        } else {
            runCatching {
                val array = JSONArray(raw)
                buildList {
                    for (index in 0 until array.length()) {
                        val item = array.optJSONObject(index) ?: continue
                        add(
                            DnsLogEntry(
                                id = item.optLong("id"),
                                timestamp = item.optString("timestamp"),
                                domain = item.optString("domain"),
                                queryType = item.optString("queryType"),
                                isBlocked = item.optBoolean("isBlocked"),
                                reason = item.optString("reason"),
                                appName = item.optString("appName")
                            )
                        )
                    }
                }
            }.getOrDefault(emptyList())
        }
        return ActivitySnapshot(
            logs = logs.take(400),
            totalAllowed = prefs.getLong(KEY_TOTAL_ALLOWED, 0L).coerceAtLeast(0L),
            totalBlocked = prefs.getLong(KEY_TOTAL_BLOCKED, 0L).coerceAtLeast(0L)
        )
    }

    fun saveActivitySnapshot(logs: List<DnsLogEntry>, totalAllowed: Long, totalBlocked: Long) {
        val array = JSONArray()
        logs.take(400).forEach { entry ->
            array.put(
                JSONObject()
                    .put("id", entry.id)
                    .put("timestamp", entry.timestamp)
                    .put("domain", entry.domain)
                    .put("queryType", entry.queryType)
                    .put("isBlocked", entry.isBlocked)
                    .put("reason", entry.reason)
                    .put("appName", entry.appName)
            )
        }
        prefs.edit()
            .putString(KEY_ACTIVITY_LOGS, array.toString())
            .putLong(KEY_TOTAL_ALLOWED, totalAllowed.coerceAtLeast(0L))
            .putLong(KEY_TOTAL_BLOCKED, totalBlocked.coerceAtLeast(0L))
            .apply()
    }

    fun clearActivitySnapshot() {
        prefs.edit()
            .remove(KEY_ACTIVITY_LOGS)
            .putLong(KEY_TOTAL_ALLOWED, 0L)
            .putLong(KEY_TOTAL_BLOCKED, 0L)
            .apply()
    }

}
