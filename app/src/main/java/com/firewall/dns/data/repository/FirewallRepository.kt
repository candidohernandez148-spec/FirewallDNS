package com.firewall.dns.data.repository

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.firewall.dns.data.local.BlocklistDataSource
import com.firewall.dns.data.local.BlocklistSnapshot
import com.firewall.dns.data.local.PreferencesDataSource
import com.firewall.dns.domain.ai.LocalAiEvidenceBuilder
import com.firewall.dns.domain.ai.LocalAiDomainSuggestion
import com.firewall.dns.domain.ai.LocalAiPolicyGate
import com.firewall.dns.domain.ai.LocalAiPolicyOutcome
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
import com.firewalldns.engine.core.FlowProtocol
import com.firewalldns.engine.core.NetworkFlowPolicyEngine
import com.firewalldns.engine.core.NetworkFlowRule
import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.core.RuleSource
import com.firewall.dns.service.FirewallTileService
import com.firewall.dns.work.BlocklistUpdateScheduler
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
    private val _localAiBlockedDomains = MutableStateFlow<List<String>>(emptyList())
    val localAiBlockedDomains: StateFlow<List<String>> = _localAiBlockedDomains.asStateFlow()
    private val _networkFlowRules = MutableStateFlow<List<NetworkFlowRule>>(emptyList())
    val networkFlowRules: StateFlow<List<NetworkFlowRule>> = _networkFlowRules.asStateFlow()
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
    private val localAiBlockedSet = ConcurrentHashMap.newKeySet<String>()
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
            customBlockSet.clear()
            customBlockSet.addAll(prefsDataSource.getCustomBlockSet())
            _customBlockList.value = customBlockSet.sorted()

            customAllowSet.clear()
            customAllowSet.addAll(prefsDataSource.getCustomAllowSet())
            _customAllowList.value = customAllowSet.sorted()
            localAiBlockedSet.clear()
            localAiBlockedSet.addAll(prefsDataSource.getLocalAiBlockedSet())
            _localAiBlockedDomains.value = localAiBlockedSet.sorted()
            _networkFlowRules.value = prefsDataSource.getNetworkFlowRules().filter { rule ->
                runCatching { NetworkFlowPolicyEngine(listOf(rule)) }.isSuccess
            }

            _excludedPackages.value = prefsDataSource.getExcludedPackages()
            _blockedApps.value = prefsDataSource.getBlockedApps()
            syncBlockedUids()
            val savedBlocklistUrls = prefsDataSource.getBlocklistUrls()
            val normalizedBlocklistUrls = savedBlocklistUrls.mapNotNull(BlocklistSourcePolicy::canonicalize).distinct()
            _blocklistUrls.value = normalizedBlocklistUrls
            _blocklistsDownloaded.value = normalizedBlocklistUrls.isNotEmpty() && blocklistDataSource.hasSavedBlocklists()
            if (normalizedBlocklistUrls != savedBlocklistUrls) {
                prefsDataSource.saveBlocklistUrls(normalizedBlocklistUrls)
            }
            _smartModeEnabled.value = prefsDataSource.getSmartModeEnabled()
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
            // Register the 24-hour Wi-Fi-only updater once; WorkManager keeps it unique across restarts.
            runCatching { BlocklistUpdateScheduler.schedule(appContext) }

            val generationAtStart = blocklistGeneration.get()
            ioScope.launch {
                try {
                    if (normalizedBlocklistUrls.isEmpty()) {
                        // Evita reactivar una lista descargada antigua cuando no había fuentes al iniciar.
                        blocklistDataSource.clearSavedBlocklists()
                        _blocklistsDownloaded.value = false
                    }
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
            importantBlocked = snapshot.importantBlocked.toSet(),
            importantExceptions = snapshot.importantExceptions.toSet(),
            exactBlocked = snapshot.exactBlocked.toSet(),
            exactExceptions = snapshot.exactExceptions.toSet(),
            importantExactBlocked = snapshot.importantExactBlocked.toSet(),
            importantExactExceptions = snapshot.importantExactExceptions.toSet(),
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

    /** Observation is passive telemetry, never a global bypass for blocking rules. */
    fun isObservationModeEnabled(): Boolean = false

    /** Compatibility shim for old UI callers; observation is always on. */
    fun setObservationModeEnabled(enabled: Boolean) = Unit

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
        if (updated.isEmpty()) {
            ioScope.launch {
                blocklistDownloadMutex.withLock {
                    if (_blocklistUrls.value.isEmpty()) {
                        blocklistGeneration.incrementAndGet()
                        blocklistDataSource.clearSavedBlocklists()
                        publishBlocklist(
                            BlocklistSnapshot(
                                blocked = defaultDomains.toSet(),
                                exceptions = emptySet(),
                                threatDomainsByCategory = emptyMap()
                            )
                        )
                        _blocklistsDownloaded.value = false
                        _cacheInvalidateEvent.tryEmit(Unit)
                    }
                }
            }
        }
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

    /**
     * Produces a bounded, local-only evidence prompt for the optional on-device AI.
     * Reads one immutable blocklist snapshot and the current persisted activity view.
     * This method is never called from the TUN or DNS decision path.
     */
    fun buildLocalAiSecurityPrompt(): String {
        val snapshot = activeBlocklistSnapshot
        return LocalAiEvidenceBuilder.buildPrompt(
            logs = _logs.value.toList(),
            blocklist = snapshot,
            customBlocked = customBlockSet.toSet() + localAiBlockedSet.toSet(),
            customAllowed = customAllowSet.toSet()
        )
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
            localAiBlockedSet.forEach { domain ->
                add(PolicyRule("local-ai-block:$domain", domain, action = PolicyAction.BLOCK,
                    source = RuleSource.MANAGED, priority = 20_000,
                    reason = "local_ai_advertising_or_tracker"))
            }
            snapshot.importantExceptions.forEach { domain ->
                add(PolicyRule("list-important-exception:$domain", domain, action = PolicyAction.ALLOW,
                    source = RuleSource.MANAGED, priority = 85_000, reason = "blocklist_important_exception"))
            }
            snapshot.importantExactExceptions.forEach { domain ->
                add(PolicyRule("list-important-exact-exception:$domain", domain, includeSubdomains = false,
                    action = PolicyAction.ALLOW, source = RuleSource.MANAGED, priority = 85_000,
                    reason = "blocklist_important_exact_exception"))
            }
            snapshot.importantBlocked.forEach { domain ->
                add(PolicyRule("list-important-block:$domain", domain, action = PolicyAction.BLOCK,
                    source = RuleSource.MANAGED, priority = 84_000, reason = "blocklist_important_match"))
            }
            snapshot.importantExactBlocked.forEach { domain ->
                add(PolicyRule("list-important-exact-block:$domain", domain, includeSubdomains = false,
                    action = PolicyAction.BLOCK, source = RuleSource.MANAGED, priority = 84_000,
                    reason = "blocklist_important_exact_match"))
            }
            (snapshot.exceptions - snapshot.importantExceptions).forEach { domain ->
                add(PolicyRule("list-exception:$domain", domain, action = PolicyAction.ALLOW,
                    source = RuleSource.MANAGED, priority = 80_000, reason = "blocklist_exception"))
            }
            (snapshot.exactExceptions - snapshot.importantExactExceptions).forEach { domain ->
                add(PolicyRule("list-exact-exception:$domain", domain, includeSubdomains = false,
                    action = PolicyAction.ALLOW, source = RuleSource.MANAGED, priority = 80_000,
                    reason = "blocklist_exact_exception"))
            }
            (snapshot.blocked - snapshot.importantBlocked).forEach { domain ->
                add(PolicyRule("blocklist:$domain", domain, action = PolicyAction.BLOCK,
                    source = RuleSource.MANAGED, priority = 10_000, reason = "blocklist_match"))
            }
            (snapshot.exactBlocked - snapshot.importantExactBlocked).forEach { domain ->
                add(PolicyRule("blocklist-exact:$domain", domain, includeSubdomains = false,
                    action = PolicyAction.BLOCK, source = RuleSource.MANAGED, priority = 10_000,
                    reason = "blocklist_exact_match"))
            }
        }
    }

    /** Snapshot consumed by the shared TUN flow-policy engine. */
    fun engineFlowPolicyRules(): List<NetworkFlowRule> = _networkFlowRules.value.toList()

    fun addNetworkFlowRule(
        destinationCidr: String,
        protocol: FlowProtocol?,
        destinationPort: Int?,
        appPackage: String?,
        action: PolicyAction
    ): Result<Unit> {
        val cidr = destinationCidr.trim().takeIf { it.isNotBlank() }
            ?: return Result.failure(IllegalArgumentException("Indica una IP o red CIDR."))
        val cleanPackage = appPackage?.trim()?.takeIf { it.isNotBlank() }
        val cleanPort = destinationPort
        val rule = NetworkFlowRule(
            id = "user-flow-" + java.util.UUID.randomUUID().toString(),
            action = action,
            source = RuleSource.USER,
            reason = "user_flow_rule",
            protocol = protocol,
            appPackage = cleanPackage,
            destinationCidr = cidr,
            destinationPort = cleanPort,
            priority = 100_000
        )
        return runCatching {
            // Reuse the production compiler for validation before persisting anything.
            NetworkFlowPolicyEngine(listOf(rule))
            val updated = _networkFlowRules.value + rule
            _networkFlowRules.value = updated
            prefsDataSource.saveNetworkFlowRules(updated)
            _cacheInvalidateEvent.tryEmit(Unit)
        }
    }

    fun removeNetworkFlowRule(id: String) {
        val updated = _networkFlowRules.value.filterNot { it.id == id }
        if (updated.size == _networkFlowRules.value.size) return
        _networkFlowRules.value = updated
        prefsDataSource.saveNetworkFlowRules(updated)
        _cacheInvalidateEvent.tryEmit(Unit)
    }

    fun isSmartModeEnabled(): Boolean = _smartModeEnabled.value

    fun evaluateDomain(domain: String): Pair<Boolean, String> {
        val activeRules = activeBlocklistSnapshot
        val baseEval = RuleEvaluator.evaluate(
            domain = domain,
            customAllow = customAllowSet,
            customBlock = customBlockSet,
            aiBlocked = localAiBlockedSet,
            hostExceptions = activeRules.exceptions - activeRules.importantExceptions,
            hostBlock = activeRules.blocked - activeRules.importantBlocked,
            importantExceptions = activeRules.importantExceptions,
            importantBlock = activeRules.importantBlocked,
            exactExceptions = activeRules.exactExceptions - activeRules.importantExactExceptions,
            exactBlock = activeRules.exactBlocked - activeRules.importantExactBlocked,
            importantExactExceptions = activeRules.importantExactExceptions,
            importantExactBlock = activeRules.importantExactBlocked
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
        // A direct user correction supersedes and removes any AI-managed decision.
        localAiBlockedSet.remove(clean)
        prefsDataSource.saveLocalAiBlockedSet(localAiBlockedSet.toSet())
        _localAiBlockedDomains.value = localAiBlockedSet.sorted()
        prefsDataSource.saveCustomBlockSet(customBlockSet.toSet())
        prefsDataSource.saveCustomAllowSet(customAllowSet.toSet())
        _customBlockList.value = customBlockSet.sorted()
        _customAllowList.value = customAllowSet.sorted()
        updateRulesCount()
        _cacheInvalidateEvent.tryEmit(Unit)
    }

    /**
     * Applies a validated local-model recommendation to the existing DNS policy.
     * This entry point is called only by the local AI coordinator, never by TUN callbacks.
     */
    fun applyLocalAiSuggestion(suggestion: LocalAiDomainSuggestion): LocalAiPolicyOutcome {
        val outcome = LocalAiPolicyGate.resolve(
            suggestion = suggestion,
            manualAllowed = customAllowSet.toSet(),
            manualBlocked = customBlockSet.toSet()
        )
        if (outcome == LocalAiPolicyOutcome.APPLY_AI_BLOCK) {
            val domain = LocalAiPolicyGate.normalizeDomain(suggestion.domain)
                ?: return LocalAiPolicyOutcome.OBSERVE_ONLY
            if (domain !in customAllowSet && domain !in customBlockSet) {
                localAiBlockedSet.add(domain)
                prefsDataSource.saveLocalAiBlockedSet(localAiBlockedSet.toSet())
                _localAiBlockedDomains.value = localAiBlockedSet.sorted()
                _cacheInvalidateEvent.tryEmit(Unit)
            }
        }
        return outcome
    }

    /** User correction: a manual rule replaces any AI-managed decision for this domain. */
    fun correctLocalAiDecision(domain: String, block: Boolean) {
        setCustomRule(domain, block)
    }

    fun removeCustomRule(domain: String) {
        val clean = RuleEvaluator.normalizeManualDomain(domain) ?: return
        customBlockSet.remove(clean)
        customAllowSet.remove(clean)
        localAiBlockedSet.remove(clean)
        prefsDataSource.saveLocalAiBlockedSet(localAiBlockedSet.toSet())
        _localAiBlockedDomains.value = localAiBlockedSet.sorted()
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

    fun addLog(
        domain: String,
        qType: String,
        isBlocked: Boolean,
        reason: String,
        appName: String,
        uid: Int,
        decisionAction: String
    ) {
        recordDnsDecision(
            domain = domain,
            allowed = !isBlocked,
            appName = appName,
            reason = reason,
            queryType = qType,
            uid = uid,
            decisionAction = decisionAction
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
        // Este indicador cuenta solo reglas externas (listas descargadas + reglas manuales).
        // Los dominios semilla integrados se aplican siempre, pero no se presentan como listas cargadas.
        val downloadedRules = (activeBlocklistSnapshot.blocked - defaultDomains.toSet())
            .union(activeBlocklistSnapshot.exactBlocked)
        val externalRuleCount = downloadedRules
            .union(activeBlocklistSnapshot.exceptions)
            .union(activeBlocklistSnapshot.exactExceptions)
            .union(customBlockSet)
            .union(customAllowSet)
            .size
        _stats.update { it.copy(loadedRulesCount = externalRuleCount) }
    }

    private fun recordDnsDecision(
        domain: String,
        allowed: Boolean,
        appName: String,
        reason: String,
        queryType: String,
        uid: Int = -1,
        decisionAction: String = if (allowed) "ALLOW" else "BLOCK"
    ) {
        val timestamp = timeFormatLocal.get()?.format(Date()) ?: ""
        val entry = DnsLogEntry(
            id = logCounter.incrementAndGet(),
            timestamp = timestamp,
            domain = domain,
            queryType = queryType,
            isBlocked = !allowed,
            reason = reason,
            appName = appName,
            uid = uid,
            decisionAction = decisionAction
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
