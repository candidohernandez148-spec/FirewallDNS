package com.firewall.dns.ui.screens

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.firewall.dns.domain.model.DnsLogEntry
import com.firewall.dns.domain.model.FirewallStats
import com.firewall.dns.domain.security.DnsActivityAnalyzer
import com.firewall.dns.domain.security.DnsRiskLevel

@Composable
fun SecurityCenterScreen(
    stats: FirewallStats,
    logs: List<DnsLogEntry>,
    otherVpnActive: Boolean,
    onOpenActivity: () -> Unit
) {
    val context = LocalContext.current
    val recentThreats = logs.filter { it.isBlocked && isThreatReason(it.reason) }
    val activityRisk = DnsActivityAnalyzer.assess(logs)
    val riskTitle = when {
        otherVpnActive -> "Conflicto de VPN"
        !stats.isRunning -> "Protección desactivada"
        else -> "Protección en funcionamiento"
    }
    val riskDescription = when {
        otherVpnActive -> "Otra VPN está ocupando la conexión VPN del sistema. FirewallDNS puede no estar filtrando el tráfico."
        !stats.isRunning -> "Activa FirewallDNS para aplicar el filtrado DNS configurado."
        logs.isEmpty() -> "El firewall está activo, pero todavía no hay actividad suficiente para evaluar amenazas."
        else -> "El motor " + stats.engine.ifBlank { "DNS" } + " está activo. El resumen se basa en los eventos DNS registrados."
    }
    val report = buildString {
        appendLine("INFORME DE SEGURIDAD — FirewallDNS")
        appendLine("Estado: " + if (stats.isRunning) "Activo" else "Desactivado")
        appendLine("Motor: " + stats.engine.ifBlank { "No disponible" })
        appendLine("Red: " + stats.networkType)
        appendLine("Reglas cargadas: " + stats.loadedRulesCount)
        appendLine("Consultas permitidas: " + stats.totalAllowed)
        appendLine("Consultas bloqueadas: " + stats.totalBlocked)
        appendLine("Eventos conservados: " + logs.size)
        appendLine("Coincidencias de amenaza en el historial: " + recentThreats.size)
        appendLine("Otra VPN detectada: " + if (otherVpnActive) "Sí" else "No")
        appendLine()
        appendLine("EVENTOS RECIENTES")
        logs.take(20).forEach { entry ->
            appendLine(entry.timestamp + " | " + (if (entry.isBlocked) "BLOQUEADO" else "PERMITIDO") + " | " + entry.domain + " | " + entry.reason + " | " + entry.appName)
        }
        appendLine()
        appendLine("Nota: refleja únicamente los eventos DNS registrados; no certifica la ausencia de amenazas ni inspecciona tráfico cifrado DoH/DoT de otras aplicaciones.")
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 12.dp, vertical = 9.dp),
        verticalArrangement = Arrangement.spacedBy(9.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (stats.isRunning && !otherVpnActive)
                        MaterialTheme.colorScheme.primaryContainer
                    else MaterialTheme.colorScheme.errorContainer
                )
            ) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("CENTRO DE SEGURIDAD", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
                    Text(riskTitle, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text(riskDescription, style = MaterialTheme.typography.bodyMedium)
                    Text(
                        if (stats.isRunning && !otherVpnActive) "Estado operativo" else "Requiere atención",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
        item {
            Text("Resumen de protección", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                SummaryCard("Bloqueados", stats.totalBlocked.toString(), Modifier.weight(1f))
                SummaryCard("Permitidos", stats.totalAllowed.toString(), Modifier.weight(1f))
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                SummaryCard("Reglas activas", stats.loadedRulesCount.toString(), Modifier.weight(1f))
                SummaryCard("Eventos recientes", logs.size.toString(), Modifier.weight(1f))
            }
        }
        item {
            Text("Alertas y observaciones", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (!stats.isRunning) {
                    AlertCard("Protección apagada", "El filtrado DNS no está activo. Enciende FirewallDNS desde el interruptor superior.", true)
                }
                if (otherVpnActive) {
                    AlertCard("Otra VPN está activa", "Android permite una VPN activa a la vez. Revisa los ajustes de VPN para evitar interrupciones.", true)
                }
                if (recentThreats.isNotEmpty()) {
                    AlertCard(
                        "Coincidencias bloqueadas: " + recentThreats.size,
                        "El historial contiene dominios bloqueados por reglas relacionadas con amenazas. Revisa la actividad para ver los detalles.",
                        true
                    )
                }
                if (stats.isRunning && !otherVpnActive && recentThreats.isEmpty()) {
                    AlertCard(
                        "Sin coincidencias de amenaza en el historial reciente",
                        if (logs.isEmpty()) "Aún no hay eventos suficientes. Esto no equivale a un análisis completo del dispositivo."
                        else "No se encontraron razones de bloqueo clasificadas como amenaza en los eventos conservados. Esto no garantiza que no existan amenazas.",
                        false
                    )
                }
                if (stats.loadedRulesCount == 0) {
                    AlertCard("No hay reglas cargadas", "Comprueba las listas de bloqueo para que el filtro tenga fuentes de dominios.", true)
                }
            }
        }
        item {
            Text("Análisis de actividad DNS", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            val riskLabel = when (activityRisk.level) {
                DnsRiskLevel.LOW -> "Bajo"
                DnsRiskLevel.MEDIUM -> "Moderado"
                DnsRiskLevel.HIGH -> "Elevado"
            }
            val riskColor = when (activityRisk.level) {
                DnsRiskLevel.LOW -> MaterialTheme.colorScheme.secondaryContainer
                DnsRiskLevel.MEDIUM -> MaterialTheme.colorScheme.tertiaryContainer
                DnsRiskLevel.HIGH -> MaterialTheme.colorScheme.errorContainer
            }
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = riskColor)
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Riesgo orientativo: $riskLabel", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text(
                        "Se analizaron ${activityRisk.analyzedEvents} de los últimos 50 eventos DNS conservados.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    if (activityRisk.findings.isEmpty()) {
                        Text(
                            "No se detectaron los patrones configurados en esta muestra. Esto no demuestra que el dispositivo esté libre de amenazas.",
                            style = MaterialTheme.typography.bodyMedium
                        )
                    } else {
                        activityRisk.findings.forEach { finding ->
                            Text("• $finding", style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                    Text(
                        "Las señales se basan en volumen de dominios por aplicación, repeticiones bloqueadas y nombres de host inusuales. No se realiza un escaneo del dispositivo ni se bloquea tráfico por este análisis.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        item {
            Text("Conexión y motor", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    DetailRow("Estado", if (stats.isRunning) "Activo" else "Apagado")
                    DetailRow("Motor", stats.engine.ifBlank { "No disponible" })
                    DetailRow("Tipo de red", stats.networkType)
                    DetailRow("Reglas cargadas", stats.loadedRulesCount.toString())
                    DetailRow("VPN externa", if (otherVpnActive) "Detectada" else "No detectada")
                }
            }
        }
        item {
            Text("Informe", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(
                "Genera un resumen de estadísticas y los últimos 20 eventos. Solo se comparte cuando tú pulsas el botón.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Button(
                onClick = {
                    val sendIntent = Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_SUBJECT, "Informe de seguridad FirewallDNS")
                        putExtra(Intent.EXTRA_TEXT, report)
                    }
                    context.startActivity(Intent.createChooser(sendIntent, "Compartir informe"))
                },
                modifier = Modifier.fillMaxWidth()
            ) { Text("Compartir informe") }
            OutlinedButton(onClick = onOpenActivity, modifier = Modifier.fillMaxWidth()) {
                Text("Ver historial completo")
            }
        }
    }
}

private fun isThreatReason(reason: String): Boolean {
    val value = reason.lowercase()
    return listOf("phishing", "malware", "ransomware", "botnet", "tracker", "rastreo", "sospech")
        .any(value::contains)
}

@Composable
private fun SummaryCard(label: String, value: String, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun AlertCard(title: String, message: String, attention: Boolean) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = if (attention) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surfaceVariant
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Text(message, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontWeight = FontWeight.SemiBold)
    }
}
