package com.firewall.dns.ui.screens

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.firewall.dns.service.FirewallDnsTrafficMetrics
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Diagnostics for the one production VPN service. No second VpnService is created. */
@Composable
fun IntegratedDiagnosticsScreen(
    vpnRunning: Boolean,
    engine: String,
    observedEvents: Int,
    metrics: FirewallDnsTrafficMetrics.Snapshot,
    onToggleVpn: (Boolean) -> Unit,
    onOpenVpnSettings: () -> Unit,
) {
    val context = LocalContext.current
    val report = JSONObject().apply {
        put("generatedAt", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date()))
        put("vpnRunning", vpnRunning)
        put("engine", engine)
        put("observedEvents", observedEvents)
        put("metrics", JSONObject().apply {
            put("packetsRead", metrics.packetsRead)
            put("queueRejected", metrics.queueRejected)
            put("parserRejected", metrics.parserRejected)
            put("ipv4Packets", metrics.ipv4Packets)
            put("ipv6Packets", metrics.ipv6Packets)
            put("dnsUdpPackets", metrics.dnsUdpPackets)
            put("dnsTcp", metrics.dnsTcp)
            put("malformedDns", metrics.malformedDns)
            put("dnsRejected", metrics.dnsRejected)
            put("dnsBlocked", metrics.dnsBlocked)
            put("dnsObserved", metrics.dnsObserved)
            put("dnsAllowed", metrics.dnsAllowed)
            put("cacheHits", metrics.cacheHits)
            put("cacheMisses", metrics.cacheMisses)
            put("upstreamSuccess", metrics.upstreamSuccess)
            put("upstreamFailure", metrics.upstreamFailure)
            put("noDnsResponse", metrics.noDnsResponse)
            put("packetsWritten", metrics.packetsWritten)
            put("writeErrors", metrics.writeErrors)
            put("workerErrors", metrics.workerErrors)
            put("smoltcpSessionsActive", metrics.smoltcpSessionsActive)
            put("smoltcpPacketsAccepted", metrics.smoltcpPacketsAccepted)
            put("smoltcpSessionsOpened", metrics.smoltcpSessionsOpened)
            put("smoltcpSessionsClosed", metrics.smoltcpSessionsClosed)
            put("smoltcpIngressRejected", metrics.smoltcpIngressRejected)
            put("smoltcpDataEvents", metrics.smoltcpDataEvents)
            put("smoltcpResponsesQueued", metrics.smoltcpResponsesQueued)
            put("smoltcpResponseFailures", metrics.smoltcpResponseFailures)
            put("smoltcpNativeErrors", metrics.smoltcpNativeErrors)
        })
        put("notVerified", listOf(
            "VpnService.protect upstream socket outcome (no dedicated counter)",
            "fragment reassembly success/failure (no dedicated counter)",
            "DoH/DoT/DoQ inspection",
            "long-duration CPU and battery behavior on device"
        ))
    }.toString(2)

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Diagnóstico del motor", style = MaterialTheme.typography.headlineSmall)
        Text("Lectura en tiempo real de contadores del servicio VPN productivo. No se crea una VPN de laboratorio.")
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Servicio VPN real", style = MaterialTheme.typography.titleMedium)
                Text(if (vpnRunning) "ACTIVO" else "INACTIVO",
                    color = if (vpnRunning) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.titleLarge)
                Text("Motor: $engine")
                Button(onClick = { onToggleVpn(!vpnRunning) }, modifier = Modifier.fillMaxWidth()) {
                    Text(if (vpnRunning) "Desactivar protección" else "Activar protección")
                }
                Button(onClick = onOpenVpnSettings, modifier = Modifier.fillMaxWidth()) {
                    Text("Ajustes VPN de Android")
                }
            }
        }
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Tráfico observado en TUN", style = MaterialTheme.typography.titleMedium)
                Metric("Paquetes leídos", metrics.packetsRead)
                Metric("IPv4 / IPv6", metrics.ipv4Packets, metrics.ipv6Packets)
                Metric("DNS UDP / DNS TCP", metrics.dnsUdpPackets, metrics.dnsTcp)
                Metric("Respuestas escritas", metrics.packetsWritten)
                Metric("Eventos del monitor", observedEvents.toLong())
            }
        }
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Decisiones DNS", style = MaterialTheme.typography.titleMedium)
                Metric("Bloqueadas", metrics.dnsBlocked)
                Metric("Observadas", metrics.dnsObserved)
                Metric("Permitidas", metrics.dnsAllowed)
                Metric("Rechazadas / malformadas", metrics.dnsRejected, metrics.malformedDns)
                Metric("Caché aciertos / fallos", metrics.cacheHits, metrics.cacheMisses)
            }
        }
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Transporte TCP DNS · smoltcp", style = MaterialTheme.typography.titleMedium)
                Metric("Sesiones activas", metrics.smoltcpSessionsActive)
                Metric("Sesiones abiertas / cerradas", metrics.smoltcpSessionsOpened, metrics.smoltcpSessionsClosed)
                Metric("Paquetes aceptados", metrics.smoltcpPacketsAccepted)
                Metric("Rechazos de entrada", metrics.smoltcpIngressRejected)
                Metric("Errores nativos", metrics.smoltcpNativeErrors)
                Metric("Fallos al encolar respuestas", metrics.smoltcpResponseFailures)
            }
        }
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Salud del procesamiento", style = MaterialTheme.typography.titleMedium)
                Metric("Cola saturada", metrics.queueRejected)
                Metric("Parser rechazó", metrics.parserRejected)
                Metric("Errores de escritura", metrics.writeErrors)
                Metric("Errores de workers", metrics.workerErrors)
                Metric("Upstream correcto / fallido", metrics.upstreamSuccess, metrics.upstreamFailure)
                Metric("Sin respuesta DNS", metrics.noDnsResponse)
            }
        }
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Cobertura y límites", style = MaterialTheme.typography.titleMedium)
                Text("MEDIDO: contadores del recorrido TUN real mientras FirewallDNS está activo.")
                Text("NO VERIFICADO: resultado individual de VpnService.protect(), éxito del reensamblado de fragmentos y estabilidad prolongada de CPU/batería.")
                Text("Fuera del alcance de inspección DNS/53: DoH, DoT y DoQ. No se presentan como tráfico inspeccionado.")
                Button(onClick = {
                    val send = Intent(Intent.ACTION_SEND).apply {
                        type = "application/json"
                        putExtra(Intent.EXTRA_SUBJECT, "FirewallDNS - informe de diagnóstico")
                        putExtra(Intent.EXTRA_TEXT, report)
                    }
                    context.startActivity(Intent.createChooser(send, "Compartir informe de diagnóstico"))
                }, modifier = Modifier.fillMaxWidth()) {
                    Text("Exportar / compartir informe JSON")
                }
            }
        }
    }
}

@Composable
private fun Metric(label: String, first: Long, second: Long? = null) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(if (second == null) first.toString() else "$first / $second",
            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
    }
}
