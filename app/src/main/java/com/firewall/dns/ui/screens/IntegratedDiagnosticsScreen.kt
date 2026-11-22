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
import com.firewall.dns.service.NetworkDns
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
    val physicalNetwork = NetworkDns.activeSnapshot(context)
    val report = JSONObject().apply {
        put("generatedAt", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date()))
        put("vpnRunning", vpnRunning)
        put("engine", engine)
        put("observedEvents", observedEvents)
        put("physicalNetwork", JSONObject().apply {
            put("transport", physicalNetwork.transport)
            put("validated", physicalNetwork.validated)
            put("dnsResolvers", physicalNetwork.resolvers.joinToString(","))
            put("networkAvailable", physicalNetwork.network != null)
        })
        put("metrics", JSONObject().apply {
            put("packetsRead", "N/D")
            put("queueRejected", "N/D")
            put("parserRejected", "N/D")
            put("ipv4Packets", "N/D")
            put("ipv6Packets", "N/D")
            put("dnsUdpPackets", "N/D")
            put("dnsTcp", "N/D")
            put("malformedDns", metrics.malformedDns)
            put("dnsRejected", metrics.dnsRejected)
            put("dnsBlocked", metrics.dnsBlocked)
            put("dnsObserved", metrics.dnsObserved)
            put("dnsAllowed", metrics.dnsAllowed)
            put("cacheHits", metrics.cacheHits)
            put("cacheMisses", metrics.cacheMisses)
            put("upstreamExchangeSuccess", "N/D")
            put("upstreamExchangeFailure", "N/D")
            put("upstreamAttemptFailures", "N/D")
            put("upstreamFailureTimeouts", "N/D")
            put("upstreamFailureProtection", "N/D")
            put("upstreamFailureIo", "N/D")
            put("upstreamFailureValidation", "N/D")
            put("upstreamFailureOther", "N/D")
            put("upstreamCancelled", "N/D")
            put("upstreamResolvers", metrics.upstreamResolvers)
            put("upstreamResolverRefreshes", metrics.upstreamResolverRefreshes)
            put("upstreamResolverUpdatedAtEpochMs", metrics.upstreamResolverUpdatedAtEpochMs)
            put("upstreamProtectUdpAttempts", metrics.upstreamProtectUdpAttempts)
            put("upstreamProtectUdpSuccess", metrics.upstreamProtectUdpSuccess)
            put("upstreamProtectUdpFailure", metrics.upstreamProtectUdpFailure)
            put("upstreamProtectTcpAttempts", metrics.upstreamProtectTcpAttempts)
            put("upstreamProtectTcpSuccess", metrics.upstreamProtectTcpSuccess)
            put("upstreamProtectTcpFailure", metrics.upstreamProtectTcpFailure)
            put("noDnsResponse", metrics.noDnsResponse)
            put("packetsWritten", metrics.packetsWritten)
            put("writeErrors", metrics.writeErrors)
            put("workerErrors", metrics.workerErrors)
            put("fragmentsAccepted", metrics.fragmentsAccepted)
            put("packetsReassembled", metrics.packetsReassembled)
            put("fragmentsDroppedInvalid", metrics.fragmentsDroppedInvalid)
            put("fragmentsDroppedLimit", metrics.fragmentsDroppedLimit)
            put("fragmentAssembliesExpired", metrics.fragmentAssembliesExpired)
            put("fragmentPendingAssemblies", metrics.fragmentPendingAssemblies)
            put("fragmentBufferedBytes", metrics.fragmentBufferedBytes)
            put("firestackActive", metrics.firestackActive)
            put("flowsActive", metrics.flowsActive)
            put("flowsOpened", metrics.flowsOpened)
            put("flowsClosed", metrics.flowsClosed)
            put("flowsBlocked", metrics.flowsBlocked)
            put("flowBytesSent", metrics.flowBytesSent)
            put("flowBytesReceived", metrics.flowBytesReceived)
            put("flowCapacityRejected", metrics.flowCapacityRejected)
            put("firestackProtectAttempts", metrics.firestackProtectAttempts)
            put("firestackProtectSuccess", metrics.firestackProtectSuccess)
            put("firestackProtectFailure", metrics.firestackProtectFailure)
            put("firestackBindAttempts", metrics.firestackBindAttempts)
            put("firestackBindSuccess", metrics.firestackBindSuccess)
            put("firestackBindFailure", metrics.firestackBindFailure)
        })
        put("notVerified", listOf(
            "Firestack TCP/UDP end-to-end traffic verification on physical Wi-Fi and mobile networks",
            "fragmented traffic injection through production TUN (counters are exposed, active injection is not yet automated)",
            "long-duration throughput, CPU and battery validation on physical devices",
            "complete DoH/DoT/DoQ inspection or decryption (known DoH hostnames and standard DoT/DoQ ports are guarded; IP-only endpoints remain unverified)",
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
                Text("Red física seleccionada", style = MaterialTheme.typography.titleMedium)
                Text("Transporte: ${physicalNetwork.transport}")
                Text("Red validada: ${if (physicalNetwork.validated) "sí" else "no"}")
                Text("DNS obtenidos de esa misma red: ${physicalNetwork.resolvers.joinToString().ifBlank { "sin resolvers detectados" }}")
                Text("Los sockets upstream se enlazan a esta red antes de excluirlos del TUN.")
            }
        }
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Motor FirewallDNS en vivo", style = MaterialTheme.typography.titleMedium)
                Metric("Firestack activo (1=sí)", metrics.firestackActive)
                Metric("Flujos activos", metrics.flowsActive)
                Metric("Flujos abiertos / cerrados", metrics.flowsOpened, metrics.flowsClosed)
                Metric("Flujos bloqueados", metrics.flowsBlocked)
                Metric("Bytes enviados / recibidos", metrics.flowBytesSent, metrics.flowBytesReceived)
                Metric("Sockets protegidos / intentos", metrics.firestackProtectSuccess, metrics.firestackProtectAttempts)
                Metric("Enlaces físicos / intentos", metrics.firestackBindSuccess, metrics.firestackBindAttempts)
                Metric("Eventos del monitor", observedEvents.toLong())
            }
        }
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Decisiones DNS", style = MaterialTheme.typography.titleMedium)
                Metric("Bloqueadas", metrics.dnsBlocked)
                Metric("Observadas", metrics.dnsObserved)
                Metric("Permitidas", metrics.dnsAllowed)
            }
        }
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Pila de red Firestack / gVisor · producción", style = MaterialTheme.typography.titleMedium)
                Text(if (metrics.firestackActive == 1L) "CONECTADA AL TUN" else "NO CONECTADA")
                Metric("Flujos activos", metrics.flowsActive)
                Metric("Flujos abiertos / cerrados", metrics.flowsOpened, metrics.flowsClosed)
                Metric("Flujos bloqueados", metrics.flowsBlocked)
                Metric("Bytes enviados / recibidos", metrics.flowBytesSent, metrics.flowBytesReceived)
                Metric("Rechazos por límite de telemetría", metrics.flowCapacityRejected)
                Metric("VpnService.protect correctos / fallidos", metrics.firestackProtectSuccess, metrics.firestackProtectFailure)
                Metric("Bind a red física correctos / fallidos", metrics.firestackBindSuccess, metrics.firestackBindFailure)
            }
        }
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Salud del procesamiento", style = MaterialTheme.typography.titleMedium)
                Text("Contador de saturación de cola: N/D (sin callback conectado).")
                Text("Rechazos del parser: N/D (sin callback conectado).")
                Metric("Fragmentos aceptados / reensamblados", metrics.fragmentsAccepted, metrics.packetsReassembled)
                Metric("Fragmentos descartados inválidos / límite", metrics.fragmentsDroppedInvalid, metrics.fragmentsDroppedLimit)
                Metric("Ensamblajes pendientes / expirados", metrics.fragmentPendingAssemblies, metrics.fragmentAssembliesExpired)
                Metric("Errores de escritura", metrics.writeErrors)
                Metric("Errores de workers", metrics.workerErrors)
                Text("DNS upstream activos: ${metrics.upstreamResolvers.ifBlank { "sin datos" }}")
                Metric("Cambios de servidores DNS", metrics.upstreamResolverRefreshes)
                Text("Última actualización DNS (epoch ms): ${metrics.upstreamResolverUpdatedAtEpochMs}")
                Text("Resultados de cada intercambio DNS upstream: N/D (el callback de intentos no está conectado).")
                Text("Fallos por intento DNS upstream: N/D.")
                Text("Timeouts / errores I/O por intento: N/D.")
                Text("Fallos protect / validación por intento: N/D.")
                Text("Otros fallos / cancelaciones por intento: N/D.")
                Text(if (metrics.upstreamProtectUdpAttempts == 0L) "protect UDP: sin intentos medidos" else
                    "protect UDP: ${metrics.upstreamProtectUdpSuccess}/${metrics.upstreamProtectUdpAttempts} correctos · ${metrics.upstreamProtectUdpFailure} fallos")
                Text(if (metrics.upstreamProtectTcpAttempts == 0L) "protect TCP: sin intentos medidos" else
                    "protect TCP: ${metrics.upstreamProtectTcpSuccess}/${metrics.upstreamProtectTcpAttempts} correctos · ${metrics.upstreamProtectTcpFailure} fallos")
                Metric("Sin respuesta DNS", metrics.noDnsResponse)
            }
        }
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Cobertura y límites", style = MaterialTheme.typography.titleMedium)
                Text("MEDIDO: Firestack/gVisor procesa los flujos TCP y UDP generales que Android enruta al TUN; sus decisiones se aplican mediante la política central de FirewallDNS. Los contadores de flujos y bytes proceden de sus callbacks reales.")
                Text("MEDIDO: intentos y resultado booleano de VpnService.protect() para sockets upstream UDP/TCP. También se exponen fragmentos aceptados, paquetes reensamblados, descartes por límite/validez y ensamblajes expirados. La prueba de tráfico fragmentado a través del TUN productivo aún requiere instrumentación en dispositivo.")
                Text("DNS UDP/TCP puerto 53 se intercepta para cualquier destino. Se bloquean puertos estándar DoT/DoQ y endpoints DoH conocidos. DoH personalizado o por IP directa sobre HTTPS/443 sigue cifrado y no puede detectarse universalmente; no se afirma inspección de su contenido.")
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
