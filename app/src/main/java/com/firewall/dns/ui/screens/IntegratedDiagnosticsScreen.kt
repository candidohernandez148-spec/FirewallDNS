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
            put("tunRxBytes", metrics.tunRxBytes)
            put("tunTxBytes", metrics.tunTxBytes)
            put("nicRxPackets", metrics.nicRxPackets)
            put("nicTxPackets", metrics.nicTxPackets)
            put("nicRxBytes", metrics.nicRxBytes)
            put("nicTxBytes", metrics.nicTxBytes)
            put("nativeStatsUpdatedAtEpochMs", metrics.nativeStatsUpdatedAtEpochMs)
            put("nicChangeObservedAtEpochMs", metrics.nicChangeObservedAtEpochMs)
            put("ipChangeObservedAtEpochMs", metrics.ipChangeObservedAtEpochMs)
            put("tcpChangeObservedAtEpochMs", metrics.tcpChangeObservedAtEpochMs)
            put("udpChangeObservedAtEpochMs", metrics.udpChangeObservedAtEpochMs)
            put("icmpChangeObservedAtEpochMs", metrics.icmpChangeObservedAtEpochMs)
            put("forwardChangeObservedAtEpochMs", metrics.forwardChangeObservedAtEpochMs)
            put("tunInvalidPackets", metrics.tunInvalidPackets)
            put("tunUnknownL3Packets", metrics.tunUnknownL3Packets)
            put("tunUnknownL4Packets", metrics.tunUnknownL4Packets)
            put("tunDrops", metrics.tunDrops)
            put("ipPacketsReceived", metrics.ipPacketsReceived)
            put("ipPacketsSent", metrics.ipPacketsSent)
            put("ipInvalidPackets", metrics.ipInvalidPackets)
            put("ipReceiveErrors", metrics.ipReceiveErrors)
            put("ipSendErrors", metrics.ipSendErrors)
            put("ipForwardDrops", metrics.ipForwardDrops)
            put("ipForwardErrors", metrics.ipForwardErrors)
            put("tcpSegmentsReceived", metrics.tcpSegmentsReceived)
            put("tcpSegmentsSent", metrics.tcpSegmentsSent)
            put("tcpEstablished", metrics.tcpEstablished)
            put("tcpConnectFailures", metrics.tcpConnectFailures)
            put("tcpRetransmits", metrics.tcpRetransmits)
            put("tcpTimeouts", metrics.tcpTimeouts)
            put("tcpDrops", metrics.tcpDrops)
            put("udpPacketsReceived", metrics.udpPacketsReceived)
            put("udpPacketsSent", metrics.udpPacketsSent)
            put("udpReceiveErrors", metrics.udpReceiveErrors)
            put("udpDrops", metrics.udpDrops)
            put("icmpV4Received", metrics.icmpV4Received)
            put("icmpV4Sent", metrics.icmpV4Sent)
            put("icmpV6Received", metrics.icmpV6Received)
            put("icmpV6Sent", metrics.icmpV6Sent)
            put("nonDnsTcp", "N/D")
            put("nonDnsUdp", "N/D")
            put("tcpRstSent", "N/D")
            put("tcpRstSuppressed", "N/D")
            put("unsupportedTransport", "N/D")
            put("dnsPolicyDecisions", metrics.dnsPolicyDecisions)
            put("engineEventsDropped", metrics.engineEventsDropped)
            put("engineQueuedEvents", metrics.engineQueuedEvents)
            put("policyRuleCount", metrics.policyRuleCount)
            put("policyRevision", metrics.policyRevision)
            put("policyInstallFailures", metrics.policyInstallFailures)
            put("policyInstallStatus", metrics.policyInstallStatus)
            put("packetsRead", "N/D")
            put("queueRejected", "N/D")
            put("parserRejected", "N/D")
            put("ipv4Packets", "N/D")
            put("ipv6Packets", "N/D")
            put("dnsUdpPackets", "N/D")
            put("dnsTcp", "N/D")
            put("malformedDns", "N/D")
            put("dnsRejected", metrics.dnsRejected)
            put("dnsBlocked", metrics.dnsBlocked)
            put("dnsObserved", metrics.dnsObserved)
            put("dnsAllowed", metrics.dnsAllowed)
            put("dnsResponseCallbacks", metrics.dnsResponseCallbacks)
            put("dnsResponseComplete", metrics.dnsResponseComplete)
            put("dnsResponseOtherStatus", metrics.dnsResponseOtherStatus)
            put("dnsResponseCached", metrics.dnsResponseCached)
            put("dnsResponseLatencySamples", metrics.dnsResponseLatencySamples)
            put("dnsResponseLatencyMsTotal", metrics.dnsResponseLatencyMsTotal)
            put("dnsResponseLastStatus", metrics.dnsResponseLastStatus)
            put("cacheHits", metrics.cacheHits)
            put("cacheMisses", metrics.cacheMisses)
            put("upstreamExchangeSuccess", "N/D")
            put("upstreamReconfigurationFailures", metrics.upstreamFailure)
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
            put("upstreamProtectUdpAttempts", "N/D")
            put("upstreamProtectUdpSuccess", "N/D")
            put("upstreamProtectUdpFailure", "N/D")
            put("upstreamProtectTcpAttempts", "N/D")
            put("upstreamProtectTcpSuccess", "N/D")
            put("upstreamProtectTcpFailure", "N/D")
            put("noDnsResponse", "N/D")
            put("packetsWritten", "N/D")
            put("writeErrors", "N/D")
            put("workerErrors", "N/D")
            put("fragmentsAccepted", "N/D")
            put("packetsReassembled", "N/D")
            put("fragmentsDroppedInvalid", "N/D")
            put("fragmentsDroppedLimit", "N/D")
            put("fragmentAssembliesExpired", "N/D")
            put("fragmentPendingAssemblies", "N/D")
            put("fragmentBufferedBytes", "N/D")
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
            "Fragmented traffic injection through the production TUN is not yet automatically tested",
            "long-duration throughput, CPU and battery validation on physical devices",
            "complete DoH/DoT/DoQ inspection or decryption (known DoH hostnames and standard DoT/DoQ ports are guarded; IP-only endpoints remain unverified)",
            "Packet read/write, queue rejection, parser classification and DNS UDP/TCP transport counters are not wired to the current Firestack production callbacks",
            "Legacy fragment reassembler counters are not connected to the Firestack packet stack",
            "Per-attempt upstream DNS success, timeout and cancellation counters are not exposed by the current production adapter"
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
                Text("Respuestas DNS Firestack", style = MaterialTheme.typography.titleMedium)
                Metric("Callbacks de respuesta", metrics.dnsResponseCallbacks)
                Metric("Estado Complete / otros", metrics.dnsResponseComplete, metrics.dnsResponseOtherStatus)
                Metric("Respuestas desde caché", metrics.dnsResponseCached)
                Metric("Muestras de latencia", metrics.dnsResponseLatencySamples)
                if (metrics.dnsResponseLatencySamples > 0L) {
                    Metric("Latencia media (ms)", metrics.dnsResponseLatencyMsTotal / metrics.dnsResponseLatencySamples)
                }
                Text("Son resúmenes del callback Firestack OnResponse; puede haber más de uno por consulta. No equivalen a consultas únicas ni a intentos individuales de socket upstream.")
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
                Text("Fragmentación IPv4/IPv6: N/D (sin callback conectado al TUN productivo).")
                Text("Errores de escritura y workers del lector anterior: N/D (sin callback conectado).")
                Text("DNS upstream activos: ${metrics.upstreamResolvers.ifBlank { "sin datos" }}")
                Metric("Cambios de servidores DNS", metrics.upstreamResolverRefreshes)
                Text("Última actualización DNS (epoch ms): ${metrics.upstreamResolverUpdatedAtEpochMs}")
                Text("Resultados de cada intercambio DNS upstream: N/D (el callback de intentos no está conectado).")
                Text("Fallos por intento DNS upstream: N/D.")
                Text("Timeouts / errores I/O por intento: N/D.")
                Text("Fallos protect / validación por intento: N/D.")
                Text("Otros fallos / cancelaciones por intento: N/D.")
                Text("Protect UDP/TCP por separado: N/D; el adaptador productivo Firestack sólo publica resultados agregados.")
                Text("Sin respuesta DNS / respuestas sintetizadas: N/D (sin callback conectado).")
            }
        }
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Cobertura y límites", style = MaterialTheme.typography.titleMedium)
                Text("MEDIDO: Firestack/gVisor procesa los flujos TCP y UDP generales que Android enruta al TUN; sus decisiones se aplican mediante la política central de FirewallDNS. Los contadores de flujos y bytes proceden de sus callbacks reales.")
                Text("MEDIDO: resultados agregados de VpnService.protect() y bindSocket() de los sockets Firestack. No se separan por TCP/UDP. Los contadores del lector de paquetes y del reensamblador de fragmentos no están conectados al TUN productivo y se muestran como N/D.")
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
