package com.firewall.dns.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.ui.input.pointer.pointerInput
import androidx.activity.compose.BackHandler
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlin.math.abs
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
    isVisible: Boolean = true,
) {
    var section by remember { mutableIntStateOf(0) }
    var appDetailOpen by remember { mutableStateOf(false) }
    fun selectSection(next: Int) {
        section = next
        if (next != 1) appDetailOpen = false
    }
    BackHandler(enabled = isVisible && section > 0 && !appDetailOpen) {
        selectSection((section - 1).coerceAtLeast(0))
    }
    Column(Modifier.fillMaxSize().pointerInput(section, isVisible, appDetailOpen) {
        if (!isVisible || appDetailOpen) return@pointerInput
        val backEdgePx = 32.dp.toPx()
        val backThresholdPx = 72.dp.toPx()
        val touchSlop = viewConfiguration.touchSlop
        awaitEachGesture {
            val down = awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Initial)
            val startedAtBackEdge = down.position.x <= backEdgePx
            var totalDragX = 0f
            var totalDragY = 0f
            while (true) {
                val event = awaitPointerEvent(PointerEventPass.Initial)
                val change = event.changes.firstOrNull { it.id == down.id } ?: break
                totalDragX = change.position.x - down.position.x
                totalDragY = change.position.y - down.position.y
                val horizontalBackSwipe = totalDragX > touchSlop && totalDragX > abs(totalDragY)
                if (startedAtBackEdge && section > 0 && horizontalBackSwipe) {
                    change.consume()
                }
                if (!change.pressed) break
            }
            if (startedAtBackEdge && section > 0 &&
                totalDragX >= backThresholdPx && totalDragX > abs(totalDragY)
            ) {
                section = (section - 1).coerceAtLeast(0)
            }
        }
    }) {
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
                FilterChip(selected = section == 0, onClick = { selectSection(0) }, label = { Text("DNS y listas") })
                FilterChip(selected = section == 1, onClick = { selectSection(1) }, label = { Text("Aplicaciones") })
                FilterChip(selected = section == 2, onClick = { selectSection(2) }, label = { Text("Flujos TUN") })
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
                firestackActive = tunMetrics.firestackActive == 1L,
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
                onOpenVpnSettings = onOpenVpnSettings,
                isVisible = isVisible,
                onAppDetailVisibilityChanged = { appDetailOpen = it }
            )
        } else {
            FlowRulesScreen(rules = flowRules, onAdd = onAddFlowRule, onRemove = onRemoveFlowRule)
        }
    }
}
