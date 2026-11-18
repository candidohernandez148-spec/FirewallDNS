package com.firewall.dns.data.repository

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap
import com.firewall.dns.data.local.BlocklistDataSource
import com.firewall.dns.data.local.PreferencesDataSource
import com.firewall.dns.domain.engine.BlocklistSourcePolicy
import com.firewall.dns.domain.engine.AppFirewallManager
import com.firewall.dns.domain.engine.DomainBlocker
import com.firewall.dns.domain.engine.RuleEvaluator
import com.firewall.dns.domain.engine.SmartDomainAnalyzer
import com.firewall.dns.domain.engine.ThreatFeedCatalog
import com.firewall.dns.domain.engine.ThreatFeedCategory
import com.firewall.dns.domain.model.AppInfoItem
import com.firewall.dns.domain.model.BlocklistDownloadProgress
import com.firewall.dns.domain.model.DnsLogEntry
import com.firewall.dns.domain.model.FirewallStats
import com.firewall.dns.domain.model.TrafficPoint
import com.firewall.dns.service.NetworkDns
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

object FirewallRepository {

    private const val MAX_LOGS = 400
    private const val TRAFFIC_POINTS = 40
    private const val TRAFFIC_INTERVAL_MS = 2_000L
    private const val MAX_LEARNED_DOMAINS = 5000
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

    private val _blockedApps = MutableStateFlow<Set<String>>(emptySet())
    val blockedApps: StateFlow<Set<String>> = _blockedApps.asStateFlow()

    private val _blocklistUrls = MutableStateFlow<List<String>>(emptyList())
    val blocklistUrls: StateFlow<List<String>> = _blocklistUrls.asStateFlow()

    private val _smartModeEnabled = MutableStateFlow(true)
    val smartModeEnabled: StateFlow<Boolean> = _smartModeEnabled.asStateFlow()

    private val _observationModeEnabled = MutableStateFlow(true)
    val observationModeEnabled: StateFlow<Boolean> = _observationModeEnabled.asStateFlow()

    private val _cacheInvalidateEvent = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val cacheInvalidateEvent: SharedFlow<Unit> = _cacheInvalidateEvent.asSharedFlow()

    private val _rebuildVpnEvent = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val rebuildVpnEvent: SharedFlow<Unit> = _rebuildVpnEvent.asSharedFlow()

    private val hostBlockSet = ConcurrentHashMap.newKeySet<String>()
    private val hostExceptionSet = ConcurrentHashMap.newKeySet<String>()
    @Volatile
    private var threatDomainsByCategory: Map<ThreatFeedCategory, Set<String>> = emptyMap()
    private val customBlockSet = ConcurrentHashMap.newKeySet<String>()
    private val customAllowSet = ConcurrentHashMap.newKeySet<String>()
    private val learnedTokens = ConcurrentHashMap<String, Int>()
    private val learnedDomains = ConcurrentHashMap.newKeySet<String>()
    private val learningSaveScheduled = AtomicBoolean(false)
    private val activitySaveScheduled = AtomicBoolean(false)
    private val activityVersion = AtomicLong(0L)
    private val learningScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val logCounter = AtomicLong(0L)
    private val timeFormatLocal = object : ThreadLocal<SimpleDateFormat>() {
        override fun initialValue(): SimpleDateFormat =
            SimpleDateFormat("dd/MM HH:mm:ss", Locale.getDefault())
    }

    private val _traffic = MutableStateFlow(List(TRAFFIC_POINTS) { TrafficPoint(0, 0) })
    val traffic: StateFlow<List<TrafficPoint>> = _traffic.asStateFlow()
    private val bucketAllowed = AtomicInteger(0)
    private val bucketBlocked = AtomicInteger(0)
    private val trafficScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    init {
        trafficScope.launch {
            while (true) {
                delay(TRAFFIC_INTERVAL_MS)
                val allowed = bucketAllowed.getAndSet(0)
                val blocked = bucketBlocked.getAndSet(0)
                if (_stats.value.isRunning || allowed > 0 || blocked > 0) {
                    val point = TrafficPoint(allowed, blocked)
                    _traffic.update { (it + point).takeLast(TRAFFIC_POINTS) }
                }
            }
        }
    }

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
            startNetworkTypeMonitor()
            prefsDataSource = PreferencesDataSource(appContext)
            blocklistDataSource = BlocklistDataSource(appContext)

            customBlockSet.clear()
            customBlockSet.addAll(prefsDataSource.getCustomBlockSet())
            _customBlockList.value = customBlockSet.sorted()

            customAllowSet.clear()
            customAllowSet.addAll(prefsDataSource.getCustomAllowSet())
            _customAllowList.value = customAllowSet.sorted()

            _excludedPackages.value = prefsDataSource.getExcludedPackages()
            _blockedApps.value = prefsDataSource.getBlockedApps()
            syncBlockedUids()
            _blocklistUrls.value = prefsDataSource.getBlocklistUrls()
            _smartModeEnabled.value = prefsDataSource.getSmartModeEnabled()
            _observationModeEnabled.value = prefsDataSource.getObservationModeEnabled()
            learnedTokens.clear()
            learnedTokens.putAll(prefsDataSource.getLearnedTokens())
            val activitySnapshot = prefsDataSource.getActivitySnapshot()
            _logs.value = activitySnapshot.logs
            logCounter.set(activitySnapshot.logs.maxOfOrNull { it.id } ?: 0L)
            _stats.update {
                it.copy(
                    learnedTokens = learnedTokens.size,
                    totalAllowed = activitySnapshot.totalAllowed,
                    totalBlocked = activitySnapshot.totalBlocked
                )
            }

            val snapshot = blocklistDataSource.loadFromDisk(defaultDomains)
            hostBlockSet.clear()
            hostBlockSet.addAll(snapshot.blocked)
            hostExceptionSet.clear()
            hostExceptionSet.addAll(snapshot.exceptions)
            threatDomainsByCategory = snapshot.threatDomainsByCategory
            updateRulesCount()

            initialized = true
        }
    }

    fun getShouldRun(): Boolean = prefsDataSource.getShouldRun()

    fun setShouldRun(shouldRun: Boolean) {
        prefsDataSource.saveShouldRun(shouldRun)
    }

    // El filtro clásico de respaldo reenvía a los DNS de la red activa.
    fun getUpstreamDns(): String = NetworkDns.firstActiveDns(appContext)

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
        if (!BlocklistSourcePolicy.isAllowed(clean)) return false
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

    // Bloquea o permite todo el acceso a Internet de una app (por UID) en AppFirewallManager.
    fun toggleBlockedApp(pkg: String, uid: Int) {
        val updated = _blockedApps.value.toMutableSet()
        val nowBlocked = updated.add(pkg)
        if (!nowBlocked) updated.remove(pkg)
        _blockedApps.value = updated
        prefsDataSource.saveBlockedApps(updated)
        if (uid >= 0) AppFirewallManager.setBlocked(uid, nowBlocked)
    }

    private fun syncBlockedUids() {
        AppFirewallManager.clear()
        _blockedApps.value.forEach { pkg ->
            try {
                AppFirewallManager.setBlocked(appContext.packageManager.getApplicationInfo(pkg, 0).uid, true)
            } catch (_: PackageManager.NameNotFoundException) {}
        }
    }

    suspend fun downloadBlocklist(
        onProgress: (BlocklistDownloadProgress) -> Unit = {}
    ): Result<String> {
        val urls = _blocklistUrls.value
        val result = blocklistDataSource.downloadMultipleAndSave(
            defaultDomains, urls, ThreatFeedCatalog.signedFeedConfigs, onProgress
        )
        return result.map { snapshot ->
            hostBlockSet.clear()
            hostBlockSet.addAll(snapshot.blocked)
            hostExceptionSet.clear()
            hostExceptionSet.addAll(snapshot.exceptions)
            threatDomainsByCategory = snapshot.threatDomainsByCategory
            updateRulesCount()
            _cacheInvalidateEvent.tryEmit(Unit)
            snapshot.summary
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
        if (!baseEval.first && baseEval.second != "Permitido") {
            learnFromActivity(domain, blocked = false, step = 1)
            return baseEval
        }
        if (baseEval.first) {
            val category = if (baseEval.second.startsWith("Adblock")) {
                threatDomainsByCategory.entries.firstOrNull { (_, domains) ->
                    ThreatFeedCatalog.matchesDomainOrParent(domain, domains)
                }?.key
            } else null
            val reason = category?.let(ThreatFeedCatalog::reasonFor) ?: baseEval.second
            if (reason.startsWith("Adblock") || category != null) {
                learnFromActivity(domain, blocked = true, step = 1)
            }
            return true to reason
        }
        if (DomainBlocker.isBlocked(domain)) {
            learnFromActivity(domain, blocked = true, step = 1)
            return true to "Lista de anuncios y rastreo"
        }
        if (_smartModeEnabled.value) {
            SmartDomainAnalyzer.evaluate(domain, learnedTokens)?.let { return it }
        }
        return baseEval
    }

    private fun learnFromActivity(domain: String, blocked: Boolean, step: Int) {
        if (!_smartModeEnabled.value) return
        val key = (if (blocked) "b:" else "a:") + domain
        if (learnedDomains.size > MAX_LEARNED_DOMAINS) learnedDomains.clear()
        if (!learnedDomains.add(key)) return
        if (SmartDomainAnalyzer.updateLearning(domain, blocked, learnedTokens, step)) scheduleLearningSave()
    }

    private fun scheduleLearningSave() {
        _stats.update { it.copy(learnedTokens = learnedTokens.size) }
        if (!learningSaveScheduled.compareAndSet(false, true)) return
        learningScope.launch {
            delay(5_000)
            learningSaveScheduled.set(false)
            prefsDataSource.saveLearnedTokens(HashMap(learnedTokens))
        }
    }

    fun resetLearning() {
        learnedTokens.clear()
        learnedDomains.clear()
        prefsDataSource.saveLearnedTokens(emptyMap())
        _stats.update { it.copy(learnedTokens = 0) }
        _cacheInvalidateEvent.tryEmit(Unit)
    }

    fun setCustomRule(domain: String, block: Boolean) {
        val clean = RuleEvaluator.normalizeManualDomain(domain) ?: return
        val set = if (block) customBlockSet else customAllowSet
        val other = if (block) customAllowSet else customBlockSet
        set.add(clean)
        other.remove(clean)
        if (_smartModeEnabled.value && SmartDomainAnalyzer.updateLearning(clean, block, learnedTokens, step = 3)) {
            scheduleLearningSave()
        }
        prefsDataSource.saveCustomBlockSet(customBlockSet.toSet())
        prefsDataSource.saveCustomAllowSet(customAllowSet.toSet())
        _customBlockList.value = customBlockSet.sorted()
        _customAllowList.value = customAllowSet.sorted()
        updateRulesCount()
        _cacheInvalidateEvent.tryEmit(Unit)
    }

    fun removeCustomRule(domain: String) {
        val clean = RuleEvaluator.normalizeManualDomain(domain) ?: return
        customBlockSet.remove(clean)
        customAllowSet.remove(clean)
        prefsDataSource.saveCustomBlockSet(customBlockSet.toSet())
        prefsDataSource.saveCustomAllowSet(customAllowSet.toSet())
        _customBlockList.value = customBlockSet.sorted()
        _customAllowList.value = customAllowSet.sorted()
        updateRulesCount()
        _cacheInvalidateEvent.tryEmit(Unit)
    }

    fun clearLogs() {
        _logs.value = emptyList()
        _stats.update { it.copy(totalAllowed = 0, totalBlocked = 0) }
        activityVersion.incrementAndGet()
        prefsDataSource.clearActivitySnapshot()
    }

    // Monitor propio de la app: funciona igual con Firestack o con el respaldo DNS.
    private fun startNetworkTypeMonitor() {
        val cm = appContext.getSystemService(android.net.ConnectivityManager::class.java)
        val refresh = { setNetworkType(NetworkDns.currentType(appContext)) }
        refresh()
        val request = android.net.NetworkRequest.Builder()
            .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try {
            cm.registerNetworkCallback(request, object : android.net.ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: android.net.Network) = refresh()
                override fun onCapabilitiesChanged(network: android.net.Network, caps: android.net.NetworkCapabilities) = refresh()
                override fun onLost(network: android.net.Network) = refresh()
            })
        } catch (_: Throwable) {}
    }

    fun setNetworkType(type: String) {
        _stats.update { it.copy(networkType = type) }
    }

    fun setShouldRunAndNotify(enabled: Boolean) {
        setShouldRun(enabled)
        if (enabled) _rebuildVpnEvent.tryEmit(Unit) else _cacheInvalidateEvent.tryEmit(Unit)
    }

    fun setRunning(running: Boolean, engine: String = "") {
        _stats.update { it.copy(isRunning = running, engine = if (running) engine else "") }
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
        pm.getInstalledApplications(0)
            .filter { it.packageName != appContext.packageName }
            .map {
                AppInfoItem(
                    label = pm.getApplicationLabel(it).toString(),
                    packageName = it.packageName,
                    icon = null,
                    uid = it.uid,
                    isSystemApp = (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                )
            }
            .sortedBy { it.label.lowercase() }
    }

    private fun updateRulesCount() {
        _stats.update { it.copy(loadedRulesCount = hostBlockSet.size + customBlockSet.size) }
    }

    private fun recordDnsDecision(domain: String, allowed: Boolean, appName: String, reason: String, queryType: String) {
        val timestamp = timeFormatLocal.get()?.format(Date()) ?: ""
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
        (if (allowed) bucketAllowed else bucketBlocked).incrementAndGet()
        _stats.update { stats ->
            if (allowed) stats.copy(totalAllowed = stats.totalAllowed + 1)
            else stats.copy(totalBlocked = stats.totalBlocked + 1)
        }
        activityVersion.incrementAndGet()
        scheduleActivitySave()
    }

    // Persistencia agrupada en segundo plano: evita escrituras en el hilo de consultas DNS.
    private fun scheduleActivitySave() {
        if (!activitySaveScheduled.compareAndSet(false, true)) return
        learningScope.launch {
            var persistedVersion = -1L
            try {
                do {
                    delay(2_000)
                    val version = activityVersion.get()
                    val currentStats = _stats.value
                    prefsDataSource.saveActivitySnapshot(
                        logs = _logs.value,
                        totalAllowed = currentStats.totalAllowed,
                        totalBlocked = currentStats.totalBlocked
                    )
                    persistedVersion = version
                } while (activityVersion.get() != persistedVersion)
            } finally {
                activitySaveScheduled.set(false)
                if (activityVersion.get() != persistedVersion) scheduleActivitySave()
            }
        }
    }
}
