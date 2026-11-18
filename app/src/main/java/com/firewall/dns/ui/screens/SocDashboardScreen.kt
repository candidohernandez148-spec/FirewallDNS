package com.firewall.dns.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowForward
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

@Composable
fun SocDashboardScreen(
    stats: FirewallStats,
    logs: List<DnsLogEntry>,
    otherVpnActive: Boolean,
    blocklistsDownloaded: Boolean,
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

    // The A34's portrait layout has enough room for a compact operational overview.
    // Keep the primary status, metrics, alerts and shortcuts visible without scrolling.
    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val compact = maxHeight < 620.dp
        val sectionGap = if (compact) 5.dp else 7.dp
        val cardPadding = if (compact) 9.dp else 11.dp
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 12.dp, vertical = if (compact) 7.dp else 10.dp),
            verticalArrangement = Arrangement.spacedBy(sectionGap)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                    Text(
                        "CENTRO DE OPERACIONES",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        "Resumen de seguridad",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                }
                Surface(
                    shape = RoundedCornerShape(50),
                    color = if (operational) MaterialTheme.colorScheme.primaryContainer
                    else MaterialTheme.colorScheme.errorContainer
                ) {
                    Text(
                        if (operational) "PROTEGIDO" else "REVISAR",
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (operational) MaterialTheme.colorScheme.primaryContainer
                    else MaterialTheme.colorScheme.errorContainer
                )
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(cardPadding),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Surface(
                        shape = CircleShape,
                        color = if (operational) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(38.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                Icons.Default.Lock,
                                contentDescription = "Estado de protección",
                                tint = if (operational) MaterialTheme.colorScheme.onPrimary
                                else MaterialTheme.colorScheme.onError
                            )
                        }
                    }
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(
                            if (operational) "Protección operativa" else "Atención requerida",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            when {
                                otherVpnActive -> "Otra VPN ocupa la conexión VPN de Android."
                                !stats.isRunning -> "El filtrado DNS está desactivado."
                                else -> "Motor activo: ${stats.engine.ifBlank { "DNS" }}."
                            },
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            "Red: ${stats.networkType.ifBlank { "No disponible" }}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1
                        )
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        Text(
                            if (stats.isRunning) "ON" else "OFF",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Black
                        )
                        Text(
                            if (otherVpnActive) "VPN en conflicto" else "Firewall",
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }
            }

            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Actividad de red", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    MetricCard("Bloqueados", stats.totalBlocked.toString(), MaterialTheme.colorScheme.error, Modifier.weight(1f), compact)
                    MetricCard("Permitidos", stats.totalAllowed.toString(), MaterialTheme.colorScheme.primary, Modifier.weight(1f), compact)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    MetricCard("Reglas cargadas", stats.loadedRulesCount.toString(), MaterialTheme.colorScheme.onSurface, Modifier.weight(1f), compact)
                    MetricCard("Tasa de bloqueo", "$blockRate%", MaterialTheme.colorScheme.onSurface, Modifier.weight(1f), compact)
                }
            }

            if (!operational || !blocklistsDownloaded || threatMatches > 0) {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 11.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(Icons.Default.Lock, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                            Text("Señal de seguridad", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
                            Text(
                                when {
                                    otherVpnActive -> "Se detectó otra VPN activa."
                                    !stats.isRunning -> "Activa FirewallDNS para filtrar DNS."
                                    !blocklistsDownloaded -> "Falta descargar las listas de bloqueo."
                                    threatMatches > 0 -> "$threatMatches coincidencias de amenaza en el historial DNS."
                                    else -> "Revisa el estado de protección."
                                },
                                style = MaterialTheme.typography.bodySmall,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        IconButton(onClick = onOpenThreats) {
                            Icon(Icons.Default.ArrowForward, contentDescription = "Abrir amenazas")
                        }
                    }
                }
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "Actividad reciente",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f)
                )
                TextButton(onClick = onOpenMonitor, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)) {
                    Text("Ver todo")
                }
            }

            if (logs.isEmpty()) {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant
                ) {
                    Text(
                        "Todavía no hay eventos DNS registrados.",
                        modifier = Modifier.padding(11.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                logs.take(if (compact) 1 else 2).forEach { entry ->
                    RecentDnsEvent(entry, compact)
                }
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = onOpenMonitor,
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 9.dp)
                ) {
                    Text("Monitor DNS", maxLines = 1, style = MaterialTheme.typography.labelMedium)
                }
                Button(
                    onClick = onOpenProtection,
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 9.dp)
                ) {
                    Text("Protección", maxLines = 1, style = MaterialTheme.typography.labelMedium)
                    Spacer(Modifier.width(4.dp))
                    Icon(Icons.Default.ArrowForward, contentDescription = null, modifier = Modifier.size(16.dp))
                }
            }
        }
    }
}

@Composable
private fun MetricCard(
    label: String,
    value: String,
    valueColor: Color,
    modifier: Modifier = Modifier,
    compact: Boolean
) {
    Card(
        modifier = modifier.height(if (compact) 54.dp else 60.dp),
        shape = RoundedCornerShape(15.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            Modifier.fillMaxSize().padding(horizontal = 11.dp, vertical = 7.dp),
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                value,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = valueColor,
                maxLines = 1
            )
            Text(
                label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun RecentDnsEvent(entry: DnsLogEntry, compact: Boolean) {
    val blocked = entry.isBlocked
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(13.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Row(
            Modifier.padding(horizontal = 10.dp, vertical = if (compact) 7.dp else 9.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(9.dp)
        ) {
            Box(
                Modifier.size(8.dp).background(
                    if (blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                    CircleShape
                )
            )
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                Text(
                    entry.domain,
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    "${entry.appName} · ${entry.timestamp}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Text(
                if (blocked) "BLOQUEADO" else "PERMITIDO",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = if (blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                maxLines = 1
            )
        }
    }
}
