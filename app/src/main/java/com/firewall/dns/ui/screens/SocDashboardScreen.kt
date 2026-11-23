package com.firewall.dns.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.firewall.dns.domain.model.DnsLogEntry
import com.firewall.dns.domain.model.FirewallStats
import com.firewall.dns.service.FirewallDnsTrafficMetrics

/**
 * Compact SOC overview. The detailed protocol and flow tables remain in the
 * Monitor and Map destinations; this first screen keeps operational essentials
 * visible without requiring a vertical scroll on common phone-sized displays.
 */
@Composable
fun SocDashboardScreen(
    stats: FirewallStats,
    logs: List<DnsLogEntry>,
    otherVpnActive: Boolean,
    blocklistsDownloaded: Boolean,
    tunMetrics: FirewallDnsTrafficMetrics.Snapshot,
    onOpenMonitor: () -> Unit,
    onOpenThreats: () -> Unit,
    onOpenProtection: () -> Unit
) {
    val operational = stats.isRunning && !otherVpnActive && tunMetrics.firestackActive > 0L
    val threatMatches = logs.count { entry ->
        entry.isBlocked && listOf("phishing", "malware", "ransomware", "botnet", "tracker", "rastreo", "sospech")
            .any(entry.reason.lowercase()::contains)
    }
    val total = stats.totalAllowed + stats.totalBlocked
    val blockRate = if (total > 0) stats.totalBlocked * 100 / total else 0L
    val latestEvents = logs.take(2)

    Column(
        modifier = Modifier.fillMaxSize().padding(horizontal = 12.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(7.dp)
    ) {
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                Text(
                    "CENTRO DE OPERACIONES",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Bold
                )
                Text("Seguridad de red", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            }
            StatusPill(if (operational) "PROTEGIDO" else "REVISAR", operational)
        }

        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(17.dp),
            colors = CardDefaults.cardColors(
                containerColor = if (operational) MaterialTheme.colorScheme.primaryContainer
                else MaterialTheme.colorScheme.errorContainer
            )
        ) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Surface(
                    shape = CircleShape,
                    color = if (operational) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(38.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            Icons.Default.Lock,
                            contentDescription = "Estado de protección",
                            tint = if (operational) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onError,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        if (operational) "Protección operativa" else "Atención requerida",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        when {
                            otherVpnActive -> "Otra VPN ocupa la conexión VPN de Android."
                            !stats.isRunning -> "El servicio VPN está desactivado."
                            tunMetrics.firestackActive <= 0L -> "Firestack/gVisor no confirma actividad."
                            else -> "Firestack/gVisor · ${stats.networkType.ifBlank { "red no identificada" }}"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Text(if (stats.isRunning) "ON" else "OFF", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Black)
            }
        }

        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            CompactMetric("BLOQUEADOS", stats.totalBlocked.toString(), MaterialTheme.colorScheme.error, Modifier.weight(1f))
            CompactMetric("PERMITIDOS", stats.totalAllowed.toString(), MaterialTheme.colorScheme.primary, Modifier.weight(1f))
            CompactMetric("REGLAS", stats.loadedRulesCount.toString(), MaterialTheme.colorScheme.onSurface, Modifier.weight(1f))
            CompactMetric("BLOQUEO", "${blockRate}%", MaterialTheme.colorScheme.onSurface, Modifier.weight(1f))
        }

        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(15.dp)) {
            Column(Modifier.fillMaxWidth().padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("MOTOR TUN · MÉTRICAS REALES", Modifier.weight(1f),
                        style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                    Text(
                        if (tunMetrics.firestackActive > 0L) "EN VIVO" else "DETENIDO",
                        style = MaterialTheme.typography.labelSmall,
                        color = if (tunMetrics.firestackActive > 0L) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CompactValue("Flujos activos", tunMetrics.flowsActive.toString(), Modifier.weight(1f))
                    CompactValue("Abiertos / cerrados", "${tunMetrics.flowsOpened} / ${tunMetrics.flowsClosed}", Modifier.weight(1f))
                    CompactValue("TX / RX", "${tunMetrics.flowBytesSent} / ${tunMetrics.flowBytesReceived} B", Modifier.weight(1f))
                }
                Text(
                    "Sockets protegidos ${tunMetrics.firestackProtectSuccess}/${tunMetrics.firestackProtectAttempts} · enlaces físicos ${tunMetrics.firestackBindSuccess}/${tunMetrics.firestackBindAttempts}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }

        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(15.dp)) {
            Column(Modifier.fillMaxWidth().padding(10.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("PROTOCOLOS · FIRESTACK / gVISOR", Modifier.weight(1f),
                        style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                    val sampleAge = if (tunMetrics.nativeStatsUpdatedAtEpochMs > 0L)
                        ((System.currentTimeMillis() - tunMetrics.nativeStatsUpdatedAtEpochMs).coerceAtLeast(0L) / 1000L)
                    else null
                    Text(sampleAge?.let { "${it}s" } ?: "SIN LECTURA",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CompactValue("IP RX / TX", "${tunMetrics.ipPacketsReceived} / ${tunMetrics.ipPacketsSent}", Modifier.weight(1f))
                    CompactValue("TCP RX / TX", "${tunMetrics.tcpSegmentsReceived} / ${tunMetrics.tcpSegmentsSent}", Modifier.weight(1f))
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CompactValue("UDP RX / TX", "${tunMetrics.udpPacketsReceived} / ${tunMetrics.udpPacketsSent}", Modifier.weight(1f))
                    CompactValue("ICMP v4 / v6 RX", "${tunMetrics.icmpV4Received} / ${tunMetrics.icmpV6Received}", Modifier.weight(1f))
                }
            }
        }

        if (!operational || !blocklistsDownloaded || threatMatches > 0) {
            Surface(
                onClick = onOpenThreats,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant
            ) {
                Row(Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
                    verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Default.Lock, contentDescription = null, tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(17.dp))
                    Text(
                        when {
                            otherVpnActive -> "Otra VPN está activa."
                            !stats.isRunning -> "Activa FirewallDNS para filtrar DNS."
                            tunMetrics.firestackActive <= 0L -> "El motor no confirma el estado operativo."
                            !blocklistsDownloaded -> "Falta descargar las listas de bloqueo."
                            else -> "$threatMatches coincidencias de amenaza en el historial."
                        },
                        Modifier.weight(1f),
                        style = MaterialTheme.typography.labelSmall,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text("VER", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Bold)
                }
            }
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Actividad reciente", Modifier.weight(1f),
                style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            TextButton(onClick = onOpenMonitor, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)) {
                Text("Monitor", style = MaterialTheme.typography.labelMedium)
            }
        }
        if (latestEvents.isEmpty()) {
            Text("Todavía no hay eventos DNS registrados.", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            latestEvents.forEach { CompactDnsEvent(it) }
        }

        OutlinedButton(
            onClick = onOpenProtection,
            modifier = Modifier.fillMaxWidth().heightIn(min = 34.dp),
            contentPadding = PaddingValues(vertical = 5.dp)
        ) {
            Text("Abrir protección", style = MaterialTheme.typography.labelMedium)
        }
    }
}

@Composable
private fun StatusPill(label: String, operational: Boolean) {
    Surface(
        shape = RoundedCornerShape(50),
        color = if (operational) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.errorContainer
    ) {
        Text(label, Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun CompactMetric(label: String, value: String, tint: Color, modifier: Modifier = Modifier) {
    Card(modifier, shape = RoundedCornerShape(12.dp)) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 7.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold,
                color = tint, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(label, style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun CompactValue(label: String, value: String, modifier: Modifier = Modifier) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(value, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold,
            maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(label, style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun CompactDnsEvent(entry: DnsLogEntry) {
    val blocked = entry.isBlocked
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Box(Modifier.size(7.dp).background(
            if (blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary, CircleShape
        ))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
            Text(entry.domain, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text("${entry.appName} · ${entry.timestamp}", style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Text(if (blocked) "BLOQ." else "OK", style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            color = if (blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
    }
}
