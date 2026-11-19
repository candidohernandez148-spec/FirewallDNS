package com.firewall.dns.data.repository

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.firewall.dns.data.local.BlocklistDataSource
import com.firewall.dns.data.local.BlocklistSnapshot
import com.firewall.dns.data.local.PreferencesDataSource
import com.firewall.dns.domain.engine.BlocklistSourcePolicy
import com.firewall.dns.domain.engine.BuiltInThreatDomains
import com.firewall.dns.domain.engine.AppFirewallManager
import com.firewall.dns.domain.engine.RuleEvaluator
import com.firewall.dns.domain.engine.SmartDecisionEngine
import com.firewall.dns.domain.engine.ThreatFeedCatalog
import com.firewall.dns.domain.engine.ThreatFeedCategory
import com.firewall.dns.domain.model.AppInfoItem
import com.firewall.dns.domain.model.BlocklistDownloadProgress
import com.firewall.dns.domain.model.DnsLogEntry
import com.firewall.dns.domain.model.FirewallStats
import com.firewall.dns.domain.model.TrafficPoint
import com.firewall.dns.service.NetworkDns
import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.core.RuleSource
import com.firewall.dns.service.FirewallTileService
import kotlinx.coroutines.CompletableDeferred
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
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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
    private const val ACTIVITY_SAVE_INTERVAL_MS = 5_000L

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

    private val _blocklistsDownloaded = MutableStateFlow(false)
    val blocklistsDownloaded: StateFlow<Boolean> = _blocklistsDownloaded.asStateFlow()

    private val _smartModeEnabled = MutableStateFlow(true)
    val smartModeEnabled: StateFlow<Boolean> = _smartModeEnabled.asStateFlow()

    private val _observationModeEnabled = MutableStateFlow(true)
    val observationModeEnabled: StateFlow<Boolean> = _observationModeEnabled.asStateFlow()

    private val _cacheInvalidateEvent = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val cacheInvalidateEvent: SharedFlow<Unit> = _cacheInvalidateEvent.asSharedFlow()

    private val _closeUidConnectionsEvent = MutableSharedFlow<Int>(extraBufferCapacity = 16)
    val closeUidConnectionsEvent: SharedFlow<Int> = _closeUidConnectionsEvent.asSharedFlow()

    private val _rebuildVpnEvent = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val rebuildVpnEvent: SharedFlow<Unit> = _rebuildVpnEvent.asSharedFlow()

    // La política activa se publica como una única referencia: las consultas DNS
    // nunca observan una lista parcialmente vaciada o reconstruida.
    @Volatile
    private var activeBlocklistSnapshot = BlocklistSnapshot(
        blocked = emptySet(),
        exceptions = emptySet(),
        threatDomainsByCategory = emptyMap()
    )
    private val customBlockSet = ConcurrentHashMap.newKeySet<String>()
    private val customAllowSet = ConcurrentHashMap.newKeySet<String>()
    private val activitySaveScheduled = AtomicBoolean(false)
    private val activityVersion = AtomicLong(0L)
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val initialBlocklistLoad = CompletableDeferred<Unit>()
    private val blocklistDownloadMutex = Mutex()
    private val blocklistGeneration = AtomicLong(0L)

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

    private val defaultDomains = BuiltInThreatDomains.domains

    fun init(context: Context) {
        if (initialized) return
        synchronized(this) {
            if (initialized) return
            appContext = context.applicationContext
            startNetworkTypeMonitor()
            prefsDataSource = PreferencesDataSource(appContext)
            blocklistDataSource = BlocklistDataSource(appContext)
            _blocklistsDownloaded.value = blocklistDataSource.hasSavedBlocklists()

            customBlockSet.clear()
            customBlockSet.addAll(prefsDataSource.getCustomBlockSet())
            _customBlockList.value = customBlockSet.sorted()

            customAllowSet.clear()
            customAllowSet.addAll(prefsDataSource.getCustomAllowSet())
            _customAllowList.value = customAllowSet.sorted()

            _excludedPackages.value = prefsDataSource.getExcludedPackages()
            _blockedApps.value = prefsDataSource.getBlockedApps()
            syncBlockedUids()
            val savedBlocklistUrls = prefsDataSource.getBlocklistUrls()
            val normalizedBlocklistUrls = savedBlocklistUrls.mapNotNull(BlocklistSourcePolicy::canonicalize).distinct()
            _blocklistUrls.value = normalizedBlocklistUrls
            if (normalizedBlocklistUrls != savedBlocklistUrls) {
                prefsDataSource.saveBlocklistUrls(normalizedBlocklistUrls)
            }
            _smartModeEnabled.value = prefsDataSource.getSmartModeEnabled()
            _observationModeEnabled.value = prefsDataSource.getObservationModeEnabled()
            val activitySnapshot = prefsDataSource.getActivitySnapshot()
            _logs.value = activitySnapshot.logs
            logCounter.set(activitySnapshot.logs.maxOfOrNull { it.id } ?: 0L)
            _stats.update {
                it.copy(
                    totalAllowed = activitySnapshot.totalAllowed,
                    totalBlocked = activitySnapshot.totalBlocked
                )
            }

            // Publica las reglas semilla y carga las listas en IO para mostrar la interfaz sin demora.
            publishBlocklist(
                BlocklistSnapshot(
                    blocked = defaultDomains.toSet(),
                    exceptions = emptySet(),
                    threatDomainsByCategory = emptyMap()
                )
            )
            initialized = true

            val generationAtStart = blocklistGeneration.get()
            ioScope.launch {
                try {
                    val snapshot = blocklistDataSource.loadFromDisk(defaultDomains)
                    if (blocklistGeneration.get() == generationAtStart) {
                        publishBlocklist(snapshot)
                        _cacheInvalidateEvent.tryEmit(Unit)
                    }
                } catch (_: Exception) {
                    // Las reglas semilla permanecen activas si falla la lectura local.
                } finally {
                    initialBlocklistLoad.complete(Unit)
                }
            }
        }
    }

    /** Publishes an immutable in-memory profile snapshot for the DNS decision engine. */
    private fun publishBlocklist(snapshot: BlocklistSnapshot) {
        val published = BlocklistSnapshot(
            blocked = snapshot.blocked.toSet(),
            exceptions = snapshot.exceptions.toSet(),
            threatDomainsByCategory = snapshot.threatDomainsByCategory.mapValues { (_, domains) ->
                domains.toSet()
            },
            summary = snapshot.summary
        )
        // Sincroniza el evaluador determinista antes de publicar el snapshot completo.
        SmartDecisionEngine.updateBlocklistKnowledge(published.blocked)
        activeBlocklistSnapshot = published
        updateRulesCount()
    }

    suspend fun awaitInitialBlocklistLoad() {
        initialBlocklistLoad.await()
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
        val clean = BlocklistSourcePolicy.canonicalize(rawUrl) ?: return false
        val current = _blocklistUrls.value.mapNotNull(BlocklistSourcePolicy::canonicalize).distinct().toMutableList()
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
        if (uid >= 0) {
            // Un UID puede pertenecer a más de un paquete: no retirar el bloqueo
            // mientras otra app con el mismo UID siga incluida en la lista.
            val uidStillBlocked = nowBlocked || updated.any { otherPackage ->
                runCatching {
                    appContext.packageManager.getApplicationInfo(otherPackage, 0).uid == uid
                }.getOrDefault(false)
            }
            AppFirewallManager.setBlocked(uid, uidStillBlocked)
            _closeUidConnectionsEvent.tryEmit(uid)
        }
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
    ): Result<String> = blocklistDownloadMutex.withLock {
        awaitInitialBlocklistLoad()
        val urls = _blocklistUrls.value
        val result = blocklistDataSource.downloadMultipleAndSave(
            defaultDomains, urls, ThreatFeedCatalog.signedFeedConfigs, onProgress
        )
        result.map { snapshot ->
            blocklistGeneration.incrementAndGet()
            publishBlocklist(snapshot)
            _blocklistsDownloaded.value = true
            _cacheInvalidateEvent.tryEmit(Unit)
            snapshot.summary
        }
    }

    /** Exporta un snapshot inmutable para la autoridad única FirewallDNS-Engine. */
    fun enginePolicyRules(): List<PolicyRule> {
        val snapshot = activeBlocklistSnapshot
        return buildList {
            customAllowSet.forEach { domain ->
                add(PolicyRule("user-allow:$domain", domain, action = PolicyAction.ALLOW,
                    source = RuleSource.USER, priority = 100_000, reason = "custom_allow"))
            }
            customBlockSet.forEach { domain ->
                add(PolicyRule("user-block:$domain", domain, action = PolicyAction.BLOCK,
                    source = RuleSource.USER, priority = 90_000, reason = "custom_block"))
            }
            snapshot.exceptions.forEach { domain ->
                add(PolicyRule("list-exception:$domain", domain, action = PolicyAction.ALLOW,
                    source = RuleSource.MANAGED, priority = 80_000, reason = "blocklist_exception"))
            }
            snapshot.blocked.forEach { domain ->
                add(PolicyRule("blocklist:$domain", domain, action = PolicyAction.BLOCK,
                    source = RuleSource.MANAGED, priority = 10_000, reason = "blocklist_match"))
            }
        }
    }

    fun isSmartModeEnabled(): Boolean = _smartModeEnabled.value

    fun evaluateDomain(domain: String): Pair<Boolean, String> {
        val activeRules = activeBlocklistSnapshot
        val baseEval = RuleEvaluator.evaluate(
            domain = domain,
            customAllow = customAllowSet,
            customBlock = customBlockSet,
            hostExceptions = activeRules.exceptions,
            hostBlock = activeRules.blocked
        )
        if (!baseEval.first && baseEval.second != "Permitido") {
            return baseEval
        }
        if (baseEval.first) {
            val category = if (baseEval.second.startsWith("Adblock")) {
                activeRules.threatDomainsByCategory.entries.firstOrNull { (_, domains) ->
                    ThreatFeedCatalog.matchesDomainOrParent(domain, domains)
                }?.key
            } else null
            val reason = category?.let(ThreatFeedCatalog::reasonFor) ?: baseEval.second
            return true to reason
        }
        if (_smartModeEnabled.value) {
            SmartDecisionEngine.evaluate(domain)?.let { decision ->
                return (decision.level == SmartDecisionEngine.Level.BLOCK) to decision.reason
            }
        }
        return baseEval
    }

    fun setCustomRule(domain: String, block: Boolean) {
        val clean = RuleEvaluator.normalizeManualDomain(domain) ?: return
        val set = if (block) customBlockSet else customAllowSet
        val other = if (block) customAllowSet else customBlockSet
        set.add(clean)
        other.remove(clean)
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

    // Monitor propio de la app: informa el tipo de red física mientras el TUN está activo.
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
        appContext.let(FirewallTileService::requestSync)
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
        // Cuenta cada dominio una sola vez, incluso si aparece en una lista descargada
        // y también en las reglas personalizadas.
        val uniqueRuleCount = activeBlocklistSnapshot.blocked.union(customBlockSet).size
        _stats.update { it.copy(loadedRulesCount = uniqueRuleCount) }
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
        ioScope.launch {
            var persistedVersion = -1L
            try {
                do {
                    delay(ACTIVITY_SAVE_INTERVAL_MS)
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
