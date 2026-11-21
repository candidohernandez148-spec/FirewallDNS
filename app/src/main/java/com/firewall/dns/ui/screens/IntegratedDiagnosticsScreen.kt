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
    var nativeTestRunning by remember { mutableStateOf(false) }
    var nativeTestResult by remember { mutableStateOf("Prueba nativa pendiente") }
    val report = JSONObject().apply {
        put("generatedAt", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date()))
        put("vpnRunning", vpnRunning)
        put("engine", engine)
        put("observedEvents", observedEvents)
        put("nativeJniTest", nativeTestResult)
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
                "protección del hilo=${wrongOwnerResult.get()}" to (wrongOwnerResult.get() == -3),
                "colas vacías=$noUnexpectedOutput" to noUnexpectedOutput,
            )
            if (otherThread.isAlive) {
                otherThread.interrupt()
                return@use "FALLO: la prueba de propietario de hilo no terminó."
            }
            val failures = checks.filterNot { it.second }.map { it.first }
            if (failures.isEmpty()) "APROBADO: Rust/JNI smoltcp IPv4+IPv6; límites, sesión inexistente, colas y propietario del hilo verificados."
            else "FALLO: ${failures.joinToString()}"
        }
    } catch (t: Throwable) {
        "FALLO JNI: ${t.javaClass.simpleName}: ${t.message ?: "sin detalle"}"
    }
}
