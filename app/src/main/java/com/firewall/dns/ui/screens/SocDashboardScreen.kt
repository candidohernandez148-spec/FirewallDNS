package com.firewall.dns.ui.screens

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.firewall.dns.domain.model.DnsLogEntry
import com.firewall.dns.domain.model.FirewallStats
import com.firewall.dns.service.FirewallDnsTrafficMetrics

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
    val operational = stats.isRunning && !otherVpnActive
    val threatMatches = logs.count { e ->
        e.isBlocked && listOf("phishing", "malware", "ransomware", "botnet", "tracker", "rastreo", "sospech")
            .any(e.reason.lowercase()::contains)
    }
    val total = stats.totalAllowed + stats.totalBlocked
    val blockRate = if (total > 0) stats.totalBlocked * 100 / total else 0L
    val pulse = rememberInfiniteTransition(label = "dashboard-pulse")
        .animateFloat(
            initialValue = 0.48f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(1050), RepeatMode.Reverse),
            label = "status-pulse"
        ).value

    Column(
        modifier = Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text("CENTRO DE OPERACIONES", style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                Text("Seguridad de red", style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold)
                Text("Estado y actividad del motor en vivo", style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Surface(shape = RoundedCornerShape(50),
                color = if (operational) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.errorContainer) {
                Text(if (operational) "PROTEGIDO" else "REVISAR",
                    Modifier.padding(horizontal = 11.dp, vertical = 7.dp),
                    style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
            }
        }

        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(22.dp),
            colors = CardDefaults.cardColors(containerColor = if (operational)
                MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.errorContainer)) {
            Row(Modifier.fillMaxWidth().padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                Surface(shape = CircleShape,
                    color = if (operational) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(58.dp).alpha(if (operational) pulse else 1f)) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(Icons.Default.Lock, contentDescription = "Estado de protección",
                            tint = if (operational) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onError,
                            modifier = Modifier.size(27.dp))
                    }
                }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(if (operational) "Protección operativa" else "Atención requerida",
                        style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text(when {
                        otherVpnActive -> "Otra VPN ocupa la conexión VPN de Android."
                        !stats.isRunning -> "El filtrado DNS está desactivado."
                        else -> "Motor activo: ${stats.engine.ifBlank { "DNS" }}."
                    }, style = MaterialTheme.typography.bodySmall)
                    Text("Red: ${stats.networkType.ifBlank { "No disponible" }}",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(if (stats.isRunning) "ON" else "OFF",
                        style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Black)
                    Text("Firewall", style = MaterialTheme.typography.labelSmall)
                }
            }
        }

        Text("Actividad de red", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            MetricCard("Bloqueados", stats.totalBlocked.toString(), MaterialTheme.colorScheme.error, Modifier.weight(1f))
            MetricCard("Permitidos", stats.totalAllowed.toString(), MaterialTheme.colorScheme.primary, Modifier.weight(1f))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            MetricCard("Reglas externas", stats.loadedRulesCount.toString(), MaterialTheme.colorScheme.onSurface, Modifier.weight(1f))
            MetricCard("Tasa de bloqueo", "$blockRate%", MaterialTheme.colorScheme.onSurface, Modifier.weight(1f))
        }

        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(18.dp)) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Motor TUN · métricas reales", Modifier.weight(1f),
                        style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Surface(shape = CircleShape, color = MaterialTheme.colorScheme.secondaryContainer) {
                        Text("EN VIVO", Modifier.padding(horizontal = 9.dp, vertical = 5.dp),
                            style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSecondaryContainer)
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    // Mismo contador acumulado que Actividad de red: cada decisión DNS
                    // bloqueada se registra una sola vez en FirewallRepository.
                    TunMetric("Bloqueos DNS", stats.totalBlocked, Modifier.weight(1f))
                    TunMetric("Flujos activos", tunMetrics.flowsActive, Modifier.weight(1f))
                    TunMetric("Flujos rechazados", tunMetrics.flowsBlocked, Modifier.weight(1f))
                    TunMetric("Flujos abiertos", tunMetrics.flowsOpened, Modifier.weight(1f))
                }
                Text(
                    "Bloqueos DNS comparte el contador acumulado de Actividad de red. " +
                        "Flujos rechazados es una métrica distinta del transporte TUN.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Text("FirewallDNS · Firestack/gVisor: ${if (tunMetrics.firestackActive > 0) "activo" else "inactivo"}",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text("Tráfico TX/RX: ${tunMetrics.flowBytesSent} / ${tunMetrics.flowBytesReceived} bytes",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text("Sockets protegidos: ${tunMetrics.firestackProtectSuccess}/${tunMetrics.firestackProtectAttempts} · enlaces físicos: ${tunMetrics.firestackBindSuccess}/${tunMetrics.firestackBindAttempts}",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        if (!operational || !blocklistsDownloaded || threatMatches > 0) {
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                Row(Modifier.padding(13.dp), verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Icon(Icons.Default.Lock, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text("Señal de seguridad", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                        Text(when {
                            otherVpnActive -> "Se detectó otra VPN activa."
                            !stats.isRunning -> "Activa FirewallDNS para filtrar DNS."
                            !blocklistsDownloaded -> "Falta descargar las listas de bloqueo."
                            threatMatches > 0 -> "$threatMatches coincidencias de amenaza en el historial DNS."
                            else -> "Revisa el estado de protección."
                        }, style = MaterialTheme.typography.bodySmall)
                    }
                    IconButton(onClick = onOpenThreats) { Icon(Icons.Default.ArrowForward, contentDescription = "Abrir amenazas") }
                }
            }
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Actividad reciente", Modifier.weight(1f),
                style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            TextButton(onClick = onOpenMonitor) { Text("Ver todo") }
        }
        if (logs.isEmpty()) {
            Surface(Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp),
                color = MaterialTheme.colorScheme.surfaceVariant) {
                Text("Todavía no hay eventos DNS registrados.", Modifier.padding(14.dp),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            logs.take(5).forEach { RecentDnsEvent(it) }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            OutlinedButton(onClick = onOpenMonitor, Modifier.weight(1f)) { Text("Monitor DNS") }
            Button(onClick = onOpenProtection, Modifier.weight(1f)) {
                Text("Protección")
                Spacer(Modifier.width(5.dp))
                Icon(Icons.Default.ArrowForward, contentDescription = null, modifier = Modifier.size(16.dp))
            }
        }
    }
}

@Composable
private fun TunMetric(label: String, value: Long, modifier: Modifier = Modifier) {
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(value.toString(), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, maxLines = 1)
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun MetricCard(label: String, value: String, valueColor: Color, modifier: Modifier = Modifier) {
    Card(modifier = modifier, shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 13.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, color = valueColor)
            Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun RecentDnsEvent(entry: DnsLogEntry) {
    val blocked = entry.isBlocked
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp)) {
        Row(Modifier.padding(horizontal = 12.dp, vertical = 11.dp),
            verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Box(Modifier.size(9.dp).background(if (blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary, CircleShape))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(entry.domain, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold,
                    maxLines = 2, overflow = TextOverflow.Ellipsis)
                Text("${entry.appName} · ${entry.timestamp}", style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            Text(if (blocked) "BLOQUEADO" else "PERMITIDO", style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold, color = if (blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
        }
    }
}
