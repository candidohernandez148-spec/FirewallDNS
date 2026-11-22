package com.firewall.dns.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.firewall.dns.domain.model.AppInfoItem
import com.firewall.dns.domain.model.BlocklistDownloadProgress
import com.firewall.dns.domain.model.FirewallStats
import com.firewall.dns.domain.model.DnsLogEntry
import com.firewall.dns.service.FirewallDnsTrafficMetrics
import com.firewalldns.engine.core.NetworkFlowRule

@Composable
fun ProtectionHubScreen(
    stats: FirewallStats,
    tunMetrics: FirewallDnsTrafficMetrics.Snapshot,
    customBlock: List<String>,
    customAllow: List<String>,
    blocklistUrls: List<String>,
    smartModeEnabled: Boolean,
    observationModeEnabled: Boolean,
    isDownloading: Boolean,
    downloadProgress: BlocklistDownloadProgress?,
    onToggleSmartMode: (Boolean) -> Unit,
    onToggleObservationMode: (Boolean) -> Unit,
    onAddBlocklistUrl: (String) -> Unit,
    onRemoveBlocklistUrl: (String) -> Unit,
    onDownloadBlocklist: () -> Unit,
    onAddCustomRule: (String, Boolean) -> Unit,
    onRemoveCustomRule: (String) -> Unit,
    flowRules: List<NetworkFlowRule>,
    onAddFlowRule: (String, com.firewalldns.engine.core.FlowProtocol?, Int?, String?, com.firewalldns.engine.core.PolicyAction) -> Boolean,
    onRemoveFlowRule: (String) -> Unit,
    apps: List<AppInfoItem>,
    logs: List<DnsLogEntry>,
    excludedPackages: Set<String>,
    blockedApps: Set<String>,
    appSearch: String,
    onAppSearchChange: (String) -> Unit,
    onToggleBlockedApp: (AppInfoItem) -> Unit,
    onToggleExcludedApp: (String) -> Unit,
    onOpenBatteryOpt: () -> Unit,
    onOpenVpnSettings: () -> Unit,
) {
    var section by remember { mutableIntStateOf(0) }
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Centro de protección", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            Text("Reglas, listas y control de aplicaciones en un solo lugar.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(
                "TUN ${tunMetrics.tunRxBytes}/${tunMetrics.tunTxBytes} B · IP ${tunMetrics.ipPacketsReceived}/${tunMetrics.ipPacketsSent} · TCP ${tunMetrics.tcpSegmentsReceived}/${tunMetrics.tcpSegmentsSent} · UDP ${tunMetrics.udpPacketsReceived}/${tunMetrics.udpPacketsSent}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                "Firestack: ${if (tunMetrics.firestackActive > 0L) "activo" else "sin confirmación"} · Flujos activos: ${tunMetrics.flowsActive} · ICMPv4 ${tunMetrics.icmpV4Received}/${tunMetrics.icmpV4Sent} · ICMPv6 ${tunMetrics.icmpV6Received}/${tunMetrics.icmpV6Sent}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = section == 0, onClick = { section = 0 }, label = { Text("DNS y listas") })
                FilterChip(selected = section == 1, onClick = { section = 1 }, label = { Text("Aplicaciones") })
                FilterChip(selected = section == 2, onClick = { section = 2 }, label = { Text("Flujos TUN") })
            }
        }
        if (section == 0) {
            RulesScreen(
                stats = stats,
                customBlock = customBlock,
                customAllow = customAllow,
                blocklistUrls = blocklistUrls,
                smartModeEnabled = smartModeEnabled,
                observationModeEnabled = observationModeEnabled,
                isDownloading = isDownloading,
                downloadProgress = downloadProgress,
                onToggleSmartMode = onToggleSmartMode,
                onToggleObservationMode = onToggleObservationMode,
                onAddBlocklistUrl = onAddBlocklistUrl,
                onRemoveBlocklistUrl = onRemoveBlocklistUrl,
                onDownloadBlocklist = onDownloadBlocklist,
                onAddCustomRule = onAddCustomRule,
                onRemoveCustomRule = onRemoveCustomRule
            )
        } else if (section == 1) {
            AppsSettingsScreen(
                stats = stats,
                apps = apps,
                logs = logs,
                activeFlows = tunMetrics.activeFlows,
                excludedPackages = excludedPackages,
                blockedApps = blockedApps,
                onToggleBlockedApp = onToggleBlockedApp,
                appSearch = appSearch,
                onAppSearchChange = onAppSearchChange,
                onToggleExcludedApp = onToggleExcludedApp,
                onOpenBatteryOpt = onOpenBatteryOpt,
                onOpenVpnSettings = onOpenVpnSettings
            )
        } else {
            FlowRulesScreen(rules = flowRules, onAdd = onAddFlowRule, onRemove = onRemoveFlowRule)
        }
    }
}
