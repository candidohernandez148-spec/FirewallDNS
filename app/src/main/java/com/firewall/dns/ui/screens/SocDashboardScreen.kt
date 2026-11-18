package com.firewall.dns.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
    onOpenMonitor: () -> Unit,
    onOpenThreats: () -> Unit,
    onOpenProtection: () -> Unit
) {
    val operational = stats.isRunning && !otherVpnActive
    val threatMatches = logs.count { e -> e.isBlocked &&
        listOf("phishing", "malware", "ransomware", "botnet", "tracker", "rastreo", "sospech")
            .any(e.reason.lowercase()::contains) }
    val total = stats.totalAllowed + stats.totalBlocked
    val blockRate = if (total > 0) stats.totalBlocked * 100 / total else 0L

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("CENTRO DE OPERACIONES", style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                Text("Resumen de seguridad", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Text("Supervisa el filtrado DNS y el estado de protección de este dispositivo.",
                    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        item {
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = if (operational)
                    MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.errorContainer)) {
                Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Surface(shape = CircleShape, color = if (operational) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.error, modifier = Modifier.size(42.dp)) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(Icons.Default.Lock, contentDescription = "Estado de protección",
                                    tint = if (operational) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onError)
                            }
                        }
                        Column(Modifier.weight(1f)) {
                            Text(if (operational) "Protección operativa" else "Atención requerida",
                                style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                            Text(when {
                                otherVpnActive -> "Otra VPN está ocupando la conexión VPN de Android."
                                !stats.isRunning -> "El filtrado DNS está desactivado."
                                else -> "Motor activo: ${stats.engine.ifBlank { "DNS" }}."
                            }, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        StatePill(if (stats.isRunning) "Firewall activo" else "Firewall apagado")
                        StatePill(if (otherVpnActive) "Conflicto VPN" else "VPN del sistema")
                    }
                    Text("Red actual: ${stats.networkType.ifBlank { "No disponible" }}",
                        style = MaterialTheme.typography.labelLarge)
                }
            }
        }
        item {
            Text("Actividad de red", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricCard("Bloqueados", stats.totalBlocked.toString(), MaterialTheme.colorScheme.error, Modifier.weight(1f))
                MetricCard("Permitidos", stats.totalAllowed.toString(), MaterialTheme.colorScheme.primary, Modifier.weight(1f))
            }
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricCard("Reglas cargadas", stats.loadedRulesCount.toString(), MaterialTheme.colorScheme.onSurface, Modifier.weight(1f))
                MetricCard("Tasa de bloqueo", "$blockRate%", MaterialTheme.colorScheme.onSurface, Modifier.weight(1f))
            }
        }
        item {
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Lock, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Text("  Señales de seguridad", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    }
                    Text(when {
                        otherVpnActive -> "Comprueba los ajustes de VPN: se detectó otra VPN activa."
                        !stats.isRunning -> "Activa FirewallDNS para aplicar las reglas DNS."
                        stats.loadedRulesCount == 0 -> "No hay reglas cargadas. Revisa las listas de protección."
                        threatMatches > 0 -> "$threatMatches coincidencias clasificadas por el motivo de bloqueo en el historial."
                        else -> "No hay coincidencias clasificadas como amenaza en los eventos recientes."
                    }, style = MaterialTheme.typography.bodyMedium)
                    Text("Datos locales basados en eventos DNS; no equivale a un análisis completo del dispositivo.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    OutlinedButton(onClick = onOpenThreats, modifier = Modifier.fillMaxWidth()) {
                        Text("Abrir centro de amenazas"); Spacer(Modifier.weight(1f))
                        Icon(Icons.Default.ArrowForward, contentDescription = null)
                    }
                }
            }
        }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Actividad reciente", style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                OutlinedButton(onClick = onOpenMonitor, contentPadding = PaddingValues(horizontal = 12.dp)) {
                    Text("Ver todo")
                }
            }
        }
        if (logs.isEmpty()) {
            item {
                Surface(Modifier.fillMaxWidth(), shape = RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.surfaceVariant) {
                    Text("Todavía no hay eventos DNS registrados.", Modifier.padding(16.dp),
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        } else {
            items(logs.take(5), key = { it.id }) { entry ->
                RecentDnsEvent(entry)
            }
        }
        item {
            Button(onClick = onOpenProtection, modifier = Modifier.fillMaxWidth(),
                contentPadding = PaddingValues(vertical = 14.dp)) {
                Text("Administrar protección y listas"); Spacer(Modifier.weight(1f))
                Icon(Icons.Default.ArrowForward, contentDescription = null)
            }
        }
    }
}

@Composable
private fun MetricCard(label: String, value: String, valueColor: Color, modifier: Modifier = Modifier) {
    Card(modifier, shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.fillMaxWidth().padding(15.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(value, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold, color = valueColor)
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun StatePill(label: String) {
    Surface(shape = RoundedCornerShape(50), color = MaterialTheme.colorScheme.surface.copy(alpha = 0.7f)) {
        Text(label, Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun RecentDnsEvent(entry: DnsLogEntry) {
    val blocked = entry.isBlocked
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Row(Modifier.padding(13.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(11.dp)) {
            Box(Modifier.size(9.dp).background(if (blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary, CircleShape))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(entry.domain, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold,
                    maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text("${entry.appName} · ${entry.timestamp}", style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Text(if (blocked) "BLOQUEADO" else "PERMITIDO", style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold, color = if (blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
        }
    }
}
