package com.firewall.dns.data.repository

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap
import com.firewall.dns.data.local.BlocklistDataSource
import com.firewall.dns.data.local.PreferencesDataSource
import com.firewall.dns.domain.engine.NgfwAction
import com.firewall.dns.domain.engine.NgfwRule
import com.firewall.dns.domain.engine.NgfwRuleEngine
import com.firewall.dns.domain.engine.RuleEvaluator
import com.firewall.dns.domain.engine.SmartDomainAnalyzer
import com.firewall.dns.domain.model.AppInfoItem
import com.firewall.dns.domain.model.DnsLogEntry
import com.firewall.dns.domain.model.FirewallStats
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

object FirewallRepository {

    private const val MAX_LOGS = 400
    private const val ICON_SIZE_PX = 96

    private lateinit var appContext: Context
    private lateinit var prefsDataSource: PreferencesDataSource
    private lateinit var blocklistDataSource: BlocklistDataSource

    private val _logs = MutableStateFlow<List<DnsLogEntry>>(emptyList())
    val logs: StateFlow<List<DnsLogEntry>> = _logs.asStateFlow()

    private val _stats = MutableStateFlow(FirewallStats())
    val stats: StateFlow<FirewallStats> = _stats.asStateFlow()

    private val _customBlockList = MutableStateFlow<List<String>>(emptyList())
    val customBlockList: StateFlow<List<String>> = _customBlockList.asStateFlow()

    private val _customAllowList = MutableStateFlow<List<String>>(emptyList())
    val customAllowList: StateFlow<List<String>> = _customAllowList.asStateFlow()

    private val _excludedPackages = MutableStateFlow<Set<String>>(emptySet())
    val excludedPackages: StateFlow<Set<String>> = _excludedPackages.asStateFlow()

    private val _blocklistUrls = MutableStateFlow<List<String>>(emptyList())
    val blocklistUrls: StateFlow<List<String>> = _blocklistUrls.asStateFlow()

    private val _smartModeEnabled = MutableStateFlow(true)
    val smartModeEnabled: StateFlow<Boolean> = _smartModeEnabled.asStateFlow()

    private val _observationModeEnabled = MutableStateFlow(true)
    val observationModeEnabled: StateFlow<Boolean> = _observationModeEnabled.asStateFlow()

    private val _ngfwEnabled = MutableStateFlow(false)
    val ngfwEnabled: StateFlow<Boolean> = _ngfwEnabled.asStateFlow()

    private val _ngfwRules = MutableStateFlow<List<NgfwRule>>(emptyList())
    val ngfwRules: StateFlow<List<NgfwRule>> = _ngfwRules.asStateFlow()

    private val _ngfwDefaultDeny = MutableStateFlow(false)
    val ngfwDefaultDeny: StateFlow<Boolean> = _ngfwDefaultDeny.asStateFlow()

    private val _ngfwHits = MutableStateFlow<Map<String, Long>>(emptyMap())
    val ngfwHits: StateFlow<Map<String, Long>> = _ngfwHits.asStateFlow()

    private val _ngfwBlockedApps = MutableStateFlow<Set<String>>(emptySet())
    val ngfwBlockedApps: StateFlow<Set<String>> = _ngfwBlockedApps.asStateFlow()

    private val _cacheInvalidateEvent = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val cacheInvalidateEvent: SharedFlow<Unit> = _cacheInvalidateEvent.asSharedFlow()

    private val _rebuildVpnEvent = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val rebuildVpnEvent: SharedFlow<Unit> = _rebuildVpnEvent.asSharedFlow()

    private val hostBlockSet = ConcurrentHashMap.newKeySet<String>()
    private val hostExceptionSet = ConcurrentHashMap.newKeySet<String>()
    private val customBlockSet = ConcurrentHashMap.newKeySet<String>()
    private val customAllowSet = ConcurrentHashMap.newKeySet<String>()
    private val learnedTokens = ConcurrentHashMap<String, Int>()

    private val logCounter = AtomicLong(0L)

    @Volatile
    private var initialized = false

    private val defaultDomains = listOf(
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "app-measurement.com", "ads.facebook.com", "analytics.tiktok.com"
    )

    fun init(context: Context) {
        if (initialized) return
        synchronized(this) {
            if (initialized) return
            appContext = context.applicationContext
            prefsDataSource = PreferencesDataSource(appContext)
            blocklistDataSource = BlocklistDataSource(appContext)

            customBlockSet.clear()
            customBlockSet.addAll(prefsDataSource.getCustomBlockSet())
            _customBlockList.value = customBlockSet.sorted()

            customAllowSet.clear()
            customAllowSet.addAll(prefsDataSource.getCustomAllowSet())
            _customAllowList.value = customAllowSet.sorted()

            _excludedPackages.value = prefsDataSource.getExcludedPackages()
            _blocklistUrls.value = prefsDataSource.getBlocklistUrls()
            _smartModeEnabled.value = prefsDataSource.getSmartModeEnabled()
            _observationModeEnabled.value = prefsDataSource.getObservationModeEnabled()
            _ngfwEnabled.value = prefsDataSource.getNgfwEnabled()
            _ngfwRules.value = prefsDataSource.getNgfwRules().mapNotNull { NgfwRule.parse(it) }
            _ngfwBlockedApps.value = prefsDataSource.getNgfwBlockedApps()
            _ngfwDefaultDeny.value = prefsDataSource.getNgfwDefaultDeny()
            learnedTokens.clear()
            learnedTokens.putAll(prefsDataSource.getLearnedTokens())

            _stats.update { it.copy(upstreamDns = prefsDataSource.getUpstreamDns()) }

            val (loadedBlocked, loadedExceptions) = blocklistDataSource.loadFromDisk(defaultDomains)
            hostBlockSet.clear()
            hostBlockSet.addAll(loadedBlocked)
            hostExceptionSet.clear()
            hostExceptionSet.addAll(loadedExceptions)
            updateRulesCount()

            initialized = true
        }
    }

    fun getShouldRun(): Boolean = prefsDataSource.getShouldRun()

    fun setShouldRun(shouldRun: Boolean) {
        prefsDataSource.saveShouldRun(shouldRun)
    }

    fun getUpstreamDns(): String = _stats.value.upstreamDns

    fun setUpstreamDns(dnsIp: String) {
        prefsDataSource.saveUpstreamDns(dnsIp)
        _stats.update { it.copy(upstreamDns = dnsIp) }
        _cacheInvalidateEvent.tryEmit(Unit)
        _rebuildVpnEvent.tryEmit(Unit)
    }

    fun isObservationModeEnabled(): Boolean = _observationModeEnabled.value

    fun setObservationModeEnabled(enabled: Boolean) {
        _observationModeEnabled.value = enabled
        prefsDataSource.saveObservationModeEnabled(enabled)
        _cacheInvalidateEvent.tryEmit(Unit)
    }

    fun setSmartModeEnabled(enabled: Boolean) {
        _smartModeEnabled.value = enabled
        prefsDataSource.saveSmartModeEnabled(enabled)
        _cacheInvalidateEvent.tryEmit(Unit)
    }

    fun addBlocklistUrl(rawUrl: String): Boolean {
        val clean = rawUrl.trim()
        if (!clean.startsWith("http://") && !clean.startsWith("https://")) return false
        val current = _blocklistUrls.value.toMutableList()
        if (!current.contains(clean)) {
            current.add(clean)
            _blocklistUrls.value = current
            prefsDataSource.saveBlocklistUrls(current)
        }
        return true
    }

    fun removeBlocklistUrl(url: String) {
        val updated = _blocklistUrls.value.filter { it != url }
        _blocklistUrls.value = updated
        prefsDataSource.saveBlocklistUrls(updated)
    }

    fun toggleExcludedApp(pkg: String) {
        val updated = _excludedPackages.value.toMutableSet()
        if (!updated.add(pkg)) updated.remove(pkg)
        _excludedPackages.value = updated
        prefsDataSource.saveExcludedPackages(updated)
        _rebuildVpnEvent.tryEmit(Unit)
    }

    fun isNgfwEnabled(): Boolean = _ngfwEnabled.value

    fun setNgfwEnabled(enabled: Boolean) {
        _ngfwEnabled.value = enabled
        prefsDataSource.saveNgfwEnabled(enabled)
        _rebuildVpnEvent.tryEmit(Unit)
    }

    fun addNgfwRule(raw: String): Boolean {
        val rule = NgfwRule.parse(raw) ?: return false
        val updated = _ngfwRules.value.filter { it != rule } + rule
        _ngfwRules.value = updated
        prefsDataSource.saveNgfwRules(updated.map { it.text })
        return true
    }

    fun removeNgfwRule(text: String) {
        val updated = _ngfwRules.value.filter { it.text != text }
        _ngfwHits.update { it - text }
        _ngfwRules.value = updated
        prefsDataSource.saveNgfwRules(updated.map { it.text })
    }

    fun toggleNgfwBlockedApp(pkg: String) {
        val updated = _ngfwBlockedApps.value.toMutableSet()
        if (!updated.add(pkg)) updated.remove(pkg)
        _ngfwBlockedApps.value = updated
        prefsDataSource.saveNgfwBlockedApps(updated)
    }

    fun setNgfwDefaultDeny(deny: Boolean) {
        _ngfwDefaultDeny.value = deny
        prefsDataSource.saveNgfwDefaultDeny(deny)
    }

    fun moveNgfwRule(text: String, delta: Int) {
        val list = _ngfwRules.value.toMutableList()
        val from = list.indexOfFirst { it.text == text }
        val to = from + delta
        if (from < 0 || to !in list.indices) return
        list.add(to, list.removeAt(from))
        _ngfwRules.value = list
        prefsDataSource.saveNgfwRules(list.map { it.text })
    }

    fun resetNgfwHits() {
        _ngfwHits.value = emptyMap()
    }

    /** Devuelve el motivo del bloqueo o null si el flujo se permite. */
    fun evaluateFlow(packages: List<String>, proto: Int, dstIp: String, dstPort: Int): String? {
        val blockedApp = packages.firstOrNull { it in _ngfwBlockedApps.value }
        if (blockedApp != null) return "NGFW: app sin red ($blockedApp)"
        val rules = _ngfwRules.value
        val rule = NgfwRuleEngine.firstMatch(rules, packages, proto, dstIp, dstPort)
        if (rule == null) {
            return if (_ngfwDefaultDeny.value) "NGFW: política implícita (deny)" else null
        }
        _ngfwHits.update { it + (rule.text to ((it[rule.text] ?: 0L) + 1L)) }
        val id = rules.indexOf(rule) + 1
        val label = rule.name?.let { "#$id $it" } ?: "#$id ${rule.text}"
        return if (rule.action == NgfwAction.BLOCK) "NGFW deny $label" else null
    }

    suspend fun downloadBlocklist(): Result<String> {
        val urls = _blocklistUrls.value
        val result = blocklistDataSource.downloadMultipleAndSave(defaultDomains, urls)
        return result.map { (newBlocked, newExceptions, summary) ->
            hostBlockSet.clear()
            hostBlockSet.addAll(newBlocked)
            hostExceptionSet.clear()
            hostExceptionSet.addAll(newExceptions)
            updateRulesCount()
            _cacheInvalidateEvent.tryEmit(Unit)
            summary
        }
    }

    fun evaluateDomain(domain: String): Pair<Boolean, String> {
        val baseEval = RuleEvaluator.evaluate(
            domain = domain,
            customAllow = customAllowSet,
            customBlock = customBlockSet,
            hostExceptions = hostExceptionSet,
            hostBlock = hostBlockSet
        )
        if (baseEval.first || baseEval.second != "Permitido") return baseEval
        if (_smartModeEnabled.value) {
            SmartDomainAnalyzer.evaluate(domain, learnedTokens)?.let { return it }
        }
        return baseEval
    }

    fun setCustomRule(domain: String, block: Boolean) {
        val clean = RuleEvaluator.normalizeManualDomain(domain) ?: return
        val set = if (block) customBlockSet else customAllowSet
        val other = if (block) customAllowSet else customBlockSet
        set.add(clean)
        other.remove(clean)
        prefsDataSource.saveCustomBlockSet(customBlockSet)
        prefsDataSource.saveCustomAllowSet(customAllowSet)
        _customBlockList.value = customBlockSet.sorted()
        _customAllowList.value = customAllowSet.sorted()
        _cacheInvalidateEvent.tryEmit(Unit)
    }

    fun removeCustomRule(domain: String) {
        val clean = RuleEvaluator.normalizeManualDomain(domain) ?: return
        customBlockSet.remove(clean)
        customAllowSet.remove(clean)
        prefsDataSource.saveCustomBlockSet(customBlockSet)
        prefsDataSource.saveCustomAllowSet(customAllowSet)
        _customBlockList.value = customBlockSet.sorted()
        _customAllowList.value = customAllowSet.sorted()
        _cacheInvalidateEvent.tryEmit(Unit)
    }

    fun clearLogs() {
        _logs.value = emptyList()
        _stats.update { it.copy(totalAllowed = 0, totalBlocked = 0) }
    }

    fun setNetworkType(type: String) {
        _stats.update { it.copy(networkType = type) }
    }

    fun setShouldRunAndNotify(enabled: Boolean) {
        setShouldRun(enabled)
        if (enabled) _rebuildVpnEvent.tryEmit(Unit) else _cacheInvalidateEvent.tryEmit(Unit)
    }

    fun setRunning(running: Boolean) {
        _stats.update { it.copy(isRunning = running) }
    }

    fun addLog(domain: String, qType: String, isBlocked: Boolean, reason: String, appName: String) {
        recordDnsDecision(
            domain = domain,
            allowed = !isBlocked,
            appName = appName,
            reason = reason,
            queryType = qType
        )
    }

    suspend fun getInstalledUserApps(): List<AppInfoItem> = withContext(Dispatchers.IO) {
        val pm = appContext.packageManager
        pm.getInstalledApplications(PackageManager.GET_META_DATA)
            .filter { it.packageName != appContext.packageName && (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
            .map {
                val icon = try {
                    pm.getApplicationIcon(it).toBitmap(ICON_SIZE_PX, ICON_SIZE_PX).asImageBitmap()
                } catch (_: Exception) {
                    null
                }
                AppInfoItem(pm.getApplicationLabel(it).toString(), it.packageName, icon)
            }
            .sortedBy { it.label.lowercase() }
    }

    private fun updateRulesCount() {
        _stats.update { it.copy(loadedRulesCount = hostBlockSet.size + customBlockSet.size) }
    }

    private fun recordDnsDecision(domain: String, allowed: Boolean, appName: String, reason: String, queryType: String) {
        val timestamp = synchronized(SimpleDateFormat("HH:mm:ss", Locale.getDefault())) {
            SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        }
        val entry = DnsLogEntry(
            id = logCounter.incrementAndGet(),
            timestamp = timestamp,
            domain = domain,
            queryType = queryType,
            isBlocked = !allowed,
            reason = reason,
            appName = appName
        )
        _logs.update { (listOf(entry) + it).take(MAX_LOGS) }
        _stats.update { stats ->
            if (allowed) stats.copy(totalAllowed = stats.totalAllowed + 1)
            else stats.copy(totalBlocked = stats.totalBlocked + 1)
        }
    }
}
