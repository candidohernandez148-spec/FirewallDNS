package com.firewall.dns.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.firewall.dns.data.repository.FirewallRepository
import com.firewalldns.engine.core.FlowProtocol
import com.firewalldns.engine.core.NetworkFlowRule
import com.firewalldns.engine.core.PolicyAction
import com.firewall.dns.domain.model.AppInfoItem
import com.firewall.dns.domain.model.BlocklistDownloadProgress
import com.firewall.dns.domain.model.DnsLogEntry
import com.firewall.dns.domain.model.FirewallStats
import com.firewall.dns.domain.model.TrafficPoint
import com.firewall.dns.service.FirewallDnsTrafficMetrics
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.sample
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay

class FirewallViewModel(application: Application) : AndroidViewModel(application) {

    val stats: StateFlow<FirewallStats> = FirewallRepository.stats
    val activityLogs: StateFlow<List<DnsLogEntry>> = FirewallRepository.logs
    val traffic: StateFlow<List<TrafficPoint>> = FirewallRepository.traffic
    val customBlockList: StateFlow<List<String>> = FirewallRepository.customBlockList
    val customAllowList: StateFlow<List<String>> = FirewallRepository.customAllowList
    val networkFlowRules: StateFlow<List<NetworkFlowRule>> = FirewallRepository.networkFlowRules
    val excludedPackages: StateFlow<Set<String>> = FirewallRepository.excludedPackages
    val blocklistUrls: StateFlow<List<String>> = FirewallRepository.blocklistUrls
    val blocklistsDownloaded: StateFlow<Boolean> = FirewallRepository.blocklistsDownloaded
    val smartModeEnabled: StateFlow<Boolean> = FirewallRepository.smartModeEnabled
    val observationModeEnabled: StateFlow<Boolean> = FirewallRepository.observationModeEnabled
    val blockedApps: StateFlow<Set<String>> = FirewallRepository.blockedApps

    private val _tunMetrics = MutableStateFlow(FirewallDnsTrafficMetrics.snapshot())
    val tunMetrics: StateFlow<FirewallDnsTrafficMetrics.Snapshot> = _tunMetrics.asStateFlow()

    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

    private val _onlyBlocked = MutableStateFlow(false)
    val onlyBlocked: StateFlow<Boolean> = _onlyBlocked.asStateFlow()

    private val _appSearch = MutableStateFlow("")
    val appSearch: StateFlow<String> = _appSearch.asStateFlow()

    private val _isDownloading = MutableStateFlow(false)
    val isDownloading: StateFlow<Boolean> = _isDownloading.asStateFlow()

    private val _downloadProgress = MutableStateFlow<BlocklistDownloadProgress?>(null)
    val downloadProgress: StateFlow<BlocklistDownloadProgress?> = _downloadProgress.asStateFlow()

    private val _installedApps = MutableStateFlow<List<AppInfoItem>>(emptyList())

    private val _toastMessage = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val toastMessage: SharedFlow<String> = _toastMessage.asSharedFlow()

    @OptIn(FlowPreview::class)
    val filteredLogs: StateFlow<List<DnsLogEntry>> = combine(
        FirewallRepository.logs,
        _onlyBlocked,
        _searchQuery
    ) { logs, blockedOnly, query ->
        logs.filter { entry ->
            (!blockedOnly || entry.isBlocked) &&
                (query.isBlank() ||
                    entry.domain.contains(query, ignoreCase = true) ||
                    entry.appName.contains(query, ignoreCase = true))
        }
    }
        .flowOn(Dispatchers.Default)
        .sample(150)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val filteredApps: StateFlow<List<AppInfoItem>> = combine(
        _installedApps,
        _appSearch
    ) { apps, query ->
        apps.filter { app ->
            query.isBlank() ||
                app.label.contains(query, ignoreCase = true) ||
                app.packageName.contains(query, ignoreCase = true)
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    init {
        FirewallRepository.init(application)
        loadInstalledApps()
        // Muestreo ligero de contadores atómicos; no interviene en el hilo TUN.
        viewModelScope.launch {
            while (true) {
                _tunMetrics.value = FirewallDnsTrafficMetrics.snapshot()
                delay(1_000L)
            }
        }
    }

    private fun loadInstalledApps() {
        viewModelScope.launch {
            try {
                _installedApps.value = FirewallRepository.getInstalledUserApps()
            } catch (_: Exception) {
                _installedApps.value = emptyList()
            }
        }
    }

    fun shouldAutoStartVpn(): Boolean =
        FirewallRepository.getShouldRun() && !FirewallRepository.stats.value.isRunning

    fun onSearchQueryChange(query: String) { _searchQuery.value = query }

    fun onToggleOnlyBlocked() { _onlyBlocked.value = !_onlyBlocked.value }

    fun onAppSearchChange(query: String) { _appSearch.value = query }

    fun setCustomRule(domain: String, block: Boolean) {
        FirewallRepository.setCustomRule(domain, block)
    }

    fun removeCustomRule(domain: String) { FirewallRepository.removeCustomRule(domain) }

    fun addNetworkFlowRule(cidr: String, protocol: FlowProtocol?, port: Int?, appPackage: String?, action: PolicyAction) {
        FirewallRepository.addNetworkFlowRule(cidr, protocol, port, appPackage, action)
            .onFailure { error -> _toastMessage.tryEmit(error.message ?: "No se pudo guardar la regla") }
            .onSuccess { _toastMessage.tryEmit("Regla de flujo guardada y aplicada") }
    }

    fun removeNetworkFlowRule(id: String) {
        FirewallRepository.removeNetworkFlowRule(id)
        _toastMessage.tryEmit("Regla de flujo eliminada")
    }

    fun clearLogs() { FirewallRepository.clearLogs() }

    fun toggleBlockedApp(app: AppInfoItem) {
        FirewallRepository.toggleBlockedApp(app.packageName, app.uid)
    }

    fun toggleExcludedApp(packageName: String) {
        FirewallRepository.toggleExcludedApp(packageName)
    }

    fun toggleSmartMode(enabled: Boolean) {
        FirewallRepository.setSmartModeEnabled(enabled)
    }

    /** Observation runs continuously alongside blocking; there is no mode switch. */
    fun setObservationModeEnabled(enabled: Boolean) = Unit

    fun addBlocklistUrl(url: String) {
        if (FirewallRepository.addBlocklistUrl(url)) {
            _toastMessage.tryEmit("URL agregada. Pulsa Actualizar listas")
        } else {
            _toastMessage.tryEmit("Usa una URL HTTPS válida (puerto 443, sin credenciales ni fragmentos)")
        }
    }

    fun removeBlocklistUrl(url: String) { FirewallRepository.removeBlocklistUrl(url) }

    fun downloadBlocklist() {
        if (_isDownloading.value) return
        viewModelScope.launch {
            _isDownloading.value = true
            try {
                _downloadProgress.value = BlocklistDownloadProgress(0, blocklistUrls.value.size, "Preparando")
                val result = FirewallRepository.downloadBlocklist { progress ->
                    _downloadProgress.value = progress
                }
                result.onSuccess { summary -> _toastMessage.tryEmit(summary) }
                    .onFailure { err -> _toastMessage.tryEmit("Error: ${err.message}") }
            } finally {
                _isDownloading.value = false
                _downloadProgress.value = null
            }
        }
    }
}
