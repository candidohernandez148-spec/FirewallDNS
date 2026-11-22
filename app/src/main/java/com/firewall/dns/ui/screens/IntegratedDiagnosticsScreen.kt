package com.firewall.dns.ui.screens

import android.content.Intent
import android.os.SystemClock
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.firewalldns.engine.android.NativeTcpDnsTransport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicInteger
import com.firewall.dns.service.DnsFirewallService
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
    val scope = rememberCoroutineScope()
    val physicalNetwork = NetworkDns.activeSnapshot(context)
    var nativeTestRunning by remember { mutableStateOf(false) }
    var nativeTestResult by remember { mutableStateOf("Prueba nativa pendiente") }
    var tcpProbeRunning by remember { mutableStateOf(false) }
    var tcpProbeResult by remember { mutableStateOf("Prueba DNS/TCP pendiente") }
    val report = JSONObject().apply {
        put("generatedAt", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date()))
        put("vpnRunning", vpnRunning)
        put("engine", engine)
        put("observedEvents", observedEvents)
        put("nativeJniTest", nativeTestResult)
        put("forcedTcpProbe", tcpProbeResult)
        put("physicalNetwork", JSONObject().apply {
            put("transport", physicalNetwork.transport)
            put("validated", physicalNetwork.validated)
            put("dnsResolvers", physicalNetwork.resolvers.joinToString(","))
            put("networkAvailable", physicalNetwork.network != null)
        })
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
            put("upstreamAttemptFailures", metrics.upstreamAttemptFailures)
            put("upstreamFailureTimeouts", metrics.upstreamFailureTimeouts)
            put("upstreamFailureProtection", metrics.upstreamFailureProtection)
            put("upstreamFailureIo", metrics.upstreamFailureIo)
            put("upstreamFailureValidation", metrics.upstreamFailureValidation)
            put("upstreamFailureOther", metrics.upstreamFailureOther)
            put("upstreamCancelled", metrics.upstreamCancelled)
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
            put("smoltcpTransportAvailable", metrics.smoltcpTransportAvailable)
            put("smoltcpSessionsActive", metrics.smoltcpSessionsActive)
            put("smoltcpPacketsAccepted", metrics.smoltcpPacketsAccepted)
            put("smoltcpSessionsOpened", metrics.smoltcpSessionsOpened)
            put("smoltcpSessionsClosed", metrics.smoltcpSessionsClosed)
            put("smoltcpIngressRejected", metrics.smoltcpIngressRejected)
            put("smoltcpDataEvents", metrics.smoltcpDataEvents)
            put("smoltcpResponsesQueued", metrics.smoltcpResponsesQueued)
            put("smoltcpResponseFailures", metrics.smoltcpResponseFailures)
            put("smoltcpNativeErrors", metrics.smoltcpNativeErrors)
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
        })
        put("notVerified", listOf(
            "fragmented traffic injection through production TUN (counters are exposed, active injection is not yet automated)",
            "long-duration throughput, CPU and battery validation on physical devices",
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
                Text("Red física seleccionada", style = MaterialTheme.typography.titleMedium)
                Text("Transporte: ${physicalNetwork.transport}")
                Text("Red validada: ${if (physicalNetwork.validated) "sí" else "no"}")
                Text("DNS obtenidos de esa misma red: ${physicalNetwork.resolvers.joinToString().ifBlank { "sin resolvers detectados" }}")
                Text("Los sockets upstream se enlazan a esta red antes de excluirlos del TUN.")
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
                Text("Prueba directa Rust/JNI", style = MaterialTheme.typography.titleMedium)
                Text("Inicializa smoltcp IPv4/IPv6 y comprueba límites de paquetes, sesión inexistente, colas y propietario del hilo. Es una prueba nativa local, no sustituye una prueba de tráfico VPN.")
                Button(
                    enabled = !nativeTestRunning,
                    onClick = {
                        nativeTestRunning = true
                        nativeTestResult = "Ejecutando…"
                        scope.launch(Dispatchers.IO) {
                            val result = runNativeBoundaryTest()
                            withContext(Dispatchers.Main) {
                                nativeTestResult = result
                                nativeTestRunning = false
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(if (nativeTestRunning) "Ejecutando prueba nativa…" else "Ejecutar prueba Rust/JNI") }
                Text(nativeTestResult, style = MaterialTheme.typography.bodySmall)
            }
        }
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Prueba DNS/TCP upstream real", style = MaterialTheme.typography.titleMedium)
                Text("Envía una consulta DNS de prueba (example.com, tipo A) por TCP/53 a los resolvers configurados, usando los mismos sockets protegidos del servicio VPN. No crea otra VPN ni modifica las reglas. Esta prueba mide la salida upstream; no inyecta una conexión TCP/53 entrante por el TUN ni valida por sí sola smoltcp. Por eso sus contadores pueden permanecer en cero.")
                Button(
                    enabled = vpnRunning && !tcpProbeRunning,
                    onClick = {
                        tcpProbeRunning = true
                        tcpProbeResult = "Ejecutando consulta TCP/53 a los resolvers configurados…"
                        scope.launch(Dispatchers.IO) {
                            val result = runCatching {
                                DnsFirewallService.runDiagnosticTcpProbe(buildDiagnosticDnsQuery())
                            }.fold(
                                onSuccess = { bundle ->
                                    val approved = bundle.getBoolean("approved", false)
                                    val detail = bundle.getString("detail").orEmpty()
                                    (if (approved) "APROBADO: " else "FALLIDO: ") + detail
                                },
                                onFailure = { error ->
                                    "FALLIDO: ${error.javaClass.simpleName}: ${error.message ?: "sin detalle"}"
                                },
                            )
                            withContext(Dispatchers.Main) {
                                tcpProbeResult = result
                                tcpProbeRunning = false
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(if (tcpProbeRunning) "Probando TCP/53…" else "Probar DNS/TCP real") }
                Text(tcpProbeResult, style = MaterialTheme.typography.bodySmall)
                Text("La prueba solo se habilita con la VPN activa. Un resultado APROBADO exige respuesta DNS validada sobre TCP; protect() exitoso por sí solo no cuenta como aprobación.")
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
            }
        }
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("smoltcp · banco nativo de pruebas", style = MaterialTheme.typography.titleMedium)
                Text("No compite con Firestack por el descriptor TUN en el modo de producción.")
                Metric("Transporte smoltcp disponible (1=sí)", metrics.smoltcpTransportAvailable)
                Metric("Sesiones activas", metrics.smoltcpSessionsActive)
                Metric("Sesiones abiertas / cerradas", metrics.smoltcpSessionsOpened, metrics.smoltcpSessionsClosed)
                Metric("Paquetes aceptados en cola JNI", metrics.smoltcpPacketsAccepted)
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
                Metric("Fragmentos aceptados / reensamblados", metrics.fragmentsAccepted, metrics.packetsReassembled)
                Metric("Fragmentos descartados inválidos / límite", metrics.fragmentsDroppedInvalid, metrics.fragmentsDroppedLimit)
                Metric("Ensamblajes pendientes / expirados", metrics.fragmentPendingAssemblies, metrics.fragmentAssembliesExpired)
                Metric("Errores de escritura", metrics.writeErrors)
                Metric("Errores de workers", metrics.workerErrors)
                Text("DNS upstream activos: ${metrics.upstreamResolvers.ifBlank { "sin datos" }}")
                Metric("Cambios de servidores DNS", metrics.upstreamResolverRefreshes)
                Text("Última actualización DNS (epoch ms): ${metrics.upstreamResolverUpdatedAtEpochMs}")
                Metric("Upstream correcto / fallido", metrics.upstreamSuccess, metrics.upstreamFailure)
                Metric("Intentos upstream fallidos", metrics.upstreamAttemptFailures)
                Metric("Fallos timeout / I/O", metrics.upstreamFailureTimeouts, metrics.upstreamFailureIo)
                Metric("Fallos protect / validación", metrics.upstreamFailureProtection, metrics.upstreamFailureValidation)
                Metric("Otros fallos / cancelados", metrics.upstreamFailureOther, metrics.upstreamCancelled)
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
                Text("DoH, DoT y DoQ pueden atravesar la pila como tráfico cifrado, pero sus consultas internas no se inspeccionan ni se presentan como bloqueadas por dominio. La inspección DNS por dominio se aplica a consultas DNS visibles que pasan por el callback del motor.")
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


/** Consulta DNS estándar de example.com para probar el upstream TCP real. */
private fun buildDiagnosticDnsQuery(): ByteArray = byteArrayOf(
    0x4A, 0x31, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
    0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01,
)

private fun runNativeBoundaryTest(): String {
    val v4Dns = byteArrayOf(10, 77, 0, 1)
    val v4Client = byteArrayOf(10, 77, 0, 2)
    val v6Dns = ByteArray(16).apply {
        this[0] = 0x20.toByte(); this[1] = 0x01.toByte()
        this[2] = 0x0d.toByte(); this[3] = 0xb8.toByte(); this[15] = 1
    }
    val v6Client = v6Dns.copyOf().apply { this[15] = 2 }
    return try {
        val transport = NativeTcpDnsTransport.create(1500, v4Dns, v4Client, v6Dns, v6Client, 16)
            ?: return "FALLO: JNI no pudo crear smoltcp."
        transport.use { native ->
            val emptyPacket = native.enqueuePacket(byteArrayOf())
            val oversizedPacket = native.enqueuePacket(ByteArray(1501))
            val pollResult = native.poll(SystemClock.elapsedRealtime(), 0)
            val missingSession = native.queueResponse(
                Long.MAX_VALUE,
                byteArrayOf(0, 12, 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0),
            )
            val rejectedPackets = native.rejectedPackets()
            val noUnexpectedOutput = native.takePacket() == null && native.takeEvent() == null
            val wrongOwnerResult = AtomicInteger(Int.MIN_VALUE)
            val otherThread = Thread {
                wrongOwnerResult.set(native.poll(SystemClock.elapsedRealtime(), 0))
            }.apply { name = "firewalldns-diagnostic-owner-probe"; start() }
            otherThread.join(2_000)
            val checks = listOf(
                "poll=$pollResult" to (pollResult >= 0),
                "paquete vacío=$emptyPacket" to (emptyPacket == -1),
                "paquete sobredimensionado=$oversizedPacket" to (oversizedPacket == -1),
                "sesión inexistente=$missingSession" to (missingSession == -5),
                "rechazos=$rejectedPackets" to (rejectedPackets == 2L),
                "protección del hilo=${wrongOwnerResult.get()}" to (wrongOwnerResult.get() == -3),
                "colas vacías=$noUnexpectedOutput" to noUnexpectedOutput,
            )
            if (otherThread.isAlive) {
                otherThread.interrupt()
                return@use "FALLO: la prueba de propietario de hilo no terminó."
            }
            val failures = checks.filterNot { it.second }.map { it.first }
            if (failures.isEmpty()) "APROBADO: Rust/JNI smoltcp IPv4+IPv6; límites, contador de rechazos, sesión inexistente, colas y propietario del hilo verificados."
            else "FALLO: ${failures.joinToString()}"
        }
    } catch (t: Throwable) {
        "FALLO JNI: ${t.javaClass.simpleName}: ${t.message ?: "sin detalle"}"
    }
}
