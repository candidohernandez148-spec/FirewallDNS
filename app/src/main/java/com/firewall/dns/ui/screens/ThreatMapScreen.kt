package com.firewall.dns.ui.screens

import android.graphics.Paint
import android.graphics.RectF
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import com.firewall.dns.domain.engine.ThreatKnowledgeGraph
import com.firewall.dns.domain.model.DnsLogEntry
import com.firewall.dns.service.FirewallDnsTrafficMetrics
import kotlin.math.cos
import kotlin.math.abs
import kotlin.math.sin

private data class MindMapEdge(val from: String, val to: String)

private val architectureEdges = listOf(
    MindMapEdge("core", "tun"),
    MindMapEdge("tun", "firestack"),
    MindMapEdge("firestack", "nic"),
    MindMapEdge("nic", "ip"),
    MindMapEdge("ip", "tcp"),
    MindMapEdge("ip", "udp"),
    MindMapEdge("ip", "icmp"),
    MindMapEdge("ip", "fwd"),
    MindMapEdge("tcp", "dns"),
    MindMapEdge("udp", "dns"),
    MindMapEdge("dns", "decisions"),
    MindMapEdge("core", "threats"),
    MindMapEdge("threats", "decisions"),
    MindMapEdge("rules", "decisions"),
    MindMapEdge("apps", "tun"),
    MindMapEdge("decisions", "upstream"),
    MindMapEdge("decisions", "tun")
)

private data class SocApplicationRoute(val uid: Int, val label: String, val dnsEvents: Int, val flows: List<com.firewalldns.engine.monitor.ActiveFlowSnapshot>)

private data class MindMapNode(
    val id: String,
    val label: String,
    val hint: String,
    val value: String,
    val x: Float,
    val y: Float,
    val z: Float,
    val tint: Color
)

/** Animated perspective mind map. Visual motion never changes engine decisions or counters. */
@Composable
fun ThreatMapScreen(
    logs: List<DnsLogEntry>,
    customBlock: List<String>,
    customAllow: List<String>,
    tunMetrics: FirewallDnsTrafficMetrics.Snapshot,
    vpnRunning: Boolean,
    smartModeEnabled: Boolean,
    observationModeEnabled: Boolean,
    onSetRule: (String, Boolean) -> Unit,
    isVisible: Boolean = true,
) {
    var section by remember { mutableStateOf("map") }
    var selectedMapNode by remember { mutableStateOf("core") }
    val catalog = remember { ThreatKnowledgeGraph.catalogSnapshot() }
    val observedApps = logs.map { it.appName }
        .filter { it.isNotBlank() && it != "Sistema / DNS" }.distinct()
    val appRoutes = remember(logs, tunMetrics.activeFlows) {
        val logUids = logs.filter { it.uid >= 0 }.map { it.uid }
        val flowUids = tunMetrics.activeFlows.mapNotNull { it.identity.appUid }
        (logUids + flowUids).distinct().sorted().map { uid ->
            val appLogs = logs.filter { it.uid == uid }
            val appFlows = tunMetrics.activeFlows.filter { it.identity.appUid == uid }
            SocApplicationRoute(
                uid,
                appLogs.firstOrNull { it.appName.isNotBlank() && it.appName != "Sistema / DNS" }?.appName
                    ?: appFlows.firstOrNull { !it.identity.appPackage.isNullOrBlank() }?.identity?.appPackage
                    ?: "Aplicación UID $uid",
                appLogs.size,
                appFlows
            )
        }
    }
    val nodes = remember(logs, customBlock, customAllow, tunMetrics, vpnRunning, appRoutes,
        smartModeEnabled, observationModeEnabled, catalog) {
        listOf(
            MindMapNode("core", "FIREWALLDNS", "Servicio VPN", if (vpnRunning) "ACTIVO" else "DETENIDO",
                0f, 0f, 0f, Color(0xFF42D9FF)),
            MindMapNode("tun", "TUN", "Interfaz VPN · entrada / salida", "${tunMetrics.tunRxBytes} / ${tunMetrics.tunTxBytes}",
                -0.90f, -0.55f, 0.00f, Color(0xFF58D6B0)),
            MindMapNode("firestack", "FIRESTACK", "Pila de red gVisor",
                if (!vpnRunning) "DETENIDO" else if (tunMetrics.firestackActive > 0) "ACTIVO" else "SIN CONFIRMAR",
                -0.92f, -0.20f, -0.38f, Color(0xFF4EA5FF)),
            MindMapNode("nic", "NIC", "Interfaz interna Firestack", "${tunMetrics.nicRxPackets} / ${tunMetrics.nicTxPackets}",
                -1.00f, 0.10f, 0.40f, Color(0xFF68D9A5)),
            MindMapNode("ip", "IP", "Contadores agregados IPv4 + IPv6", "${tunMetrics.ipPacketsReceived} / ${tunMetrics.ipPacketsSent}",
                -0.70f, 0.70f, 0.20f, Color(0xFF78A8FF)),
            MindMapNode("tcp", "TCP", "Segmentos RX / TX", "${tunMetrics.tcpSegmentsReceived} / ${tunMetrics.tcpSegmentsSent}",
                -1.00f, 1.00f, -0.50f, Color(0xFF42D9FF)),
            MindMapNode("udp", "UDP", "Datagramas RX / TX", "${tunMetrics.udpPacketsReceived} / ${tunMetrics.udpPacketsSent}",
                -0.30f, 1.00f, -0.80f, Color(0xFF58D6B0)),
            MindMapNode("icmp", "ICMP", "Mensajes RX · IPv4 + IPv6", "${tunMetrics.icmpV4Received + tunMetrics.icmpV6Received} RX",
                0.40f, 1.00f, -0.80f, Color(0xFFFFB454)),
            MindMapNode("fwd", "FWD", "Reenvío IP", "${tunMetrics.ipForwardDrops} drops",
                1.00f, 0.55f, -0.20f, Color(0xFFB69CFF)),
            MindMapNode("dns", "DNS", "Consultas evaluadas",
                (tunMetrics.dnsBlocked + tunMetrics.dnsObserved + tunMetrics.dnsAllowed).toString(),
                0.20f, 0.35f, 0.75f, Color(0xFF78A8FF)),
            MindMapNode("decisions", "DECISIONES", "Bloquear / observar / permitir",
                "${tunMetrics.dnsBlocked} / ${tunMetrics.dnsObserved} / ${tunMetrics.dnsAllowed}",
                1.00f, -0.05f, 0.65f, Color(0xFFFF667D)),
            MindMapNode("threats", "AMENAZAS", "Catálogo local de referencia",
                catalog.size.toString(), 0.25f, 0.75f, 0.90f, Color(0xFFFFB454)),
            MindMapNode("rules", "REGLAS", "Reglas personalizadas",
                "${customBlock.size} bloqueo · ${customAllow.size} permiso",
                -0.45f, 0.45f, 0.90f, Color(0xFFB69CFF)),
            MindMapNode("upstream", "RESOLVERS", "DNS de red física",
                tunMetrics.upstreamResolverRefreshes.toString(),
                0.55f, -0.95f, 0.65f, Color(0xFF68D9A5)),
            MindMapNode("apps", "APLICACIONES", "Aplicaciones identificadas por UID / flujos",
                appRoutes.size.toString(), -0.55f, -0.95f, 0.65f, Color(0xFF58D6B0))
        )
    }
    BackHandler(enabled = isVisible && section != "map") { section = "map" }
    val selectedNode = selectedMapNode
    if (section == "map") {
        LazyColumn(
            Modifier.fillMaxSize().padding(horizontal = 8.dp, vertical = 6.dp),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 14.dp),
            verticalArrangement = Arrangement.spacedBy(9.dp)
        ) {
            item { SocHeader(vpnRunning = vpnRunning, metrics = tunMetrics) }
            item {
                ThreeDimensionalMindMap(
                    nodes = nodes,
                    selectedNode = selectedNode,
                    lastDnsDecisionAtEpochMs = tunMetrics.lastDnsDecisionAtEpochMs,
                    lastFlowEventAtEpochMs = tunMetrics.lastFlowEventAtEpochMs,
                    metrics = tunMetrics,
                    activeFlowCount = tunMetrics.flowsActive,
                    appRoutes = appRoutes,
                    vpnRunning = vpnRunning
                ) { id ->
                    selectedMapNode = id
                }
            }
            item {
                SocArchitectureLayers(observedApps = appRoutes.size, metrics = tunMetrics)
            }
            item { SocKpiGrid(metrics = tunMetrics) }
            item { SocPolicyDiagnostics(metrics = tunMetrics) }
            item { SocTunnelPath(metrics = tunMetrics, vpnRunning = vpnRunning) }
            item { LiveMapTelemetry(metrics = tunMetrics, logs = logs, vpnRunning = vpnRunning) }
            item { SocAppDnsActivity(logs = logs, flows = tunMetrics.activeFlows) }
            item {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                    MindMapAction("Motor", "red", "⚙") { section = it }
                    MindMapAction("DNS", "dns", "⇄") { section = it }
                    MindMapAction("Amenazas", "amenazas", "⚠") { section = it }
                    MindMapAction("Reglas", "reglas", "☷") { section = it }
                    MindMapAction("Apps", "apps", "▦") { section = it }
                }
            }
            item {
                Text(
                    "CENTRO DE OPERACIONES · Datos provenientes de métricas y eventos del servicio. La animación 3D representa la arquitectura, no paquetes individuales.",
                    Modifier.fillMaxWidth().padding(horizontal = 5.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    } else {
        Column(Modifier.fillMaxSize().pointerInput(section, isVisible) {
            if (!isVisible) return@pointerInput
            val backEdgePx = 32.dp.toPx()
            val backThresholdPx = 72.dp.toPx()
            val touchSlop = viewConfiguration.touchSlop
            awaitEachGesture {
                val down = awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Initial)
                val startedAtBackEdge = down.position.x <= backEdgePx
                var totalDragX = 0f
                var totalDragY = 0f
                while (true) {
                    val event = awaitPointerEvent(PointerEventPass.Initial)
                    val change = event.changes.firstOrNull { it.id == down.id } ?: break
                    totalDragX = change.position.x - down.position.x
                    totalDragY = change.position.y - down.position.y
                    val horizontalBackSwipe = totalDragX > touchSlop && totalDragX > abs(totalDragY)
                    if (startedAtBackEdge && horizontalBackSwipe) {
                        change.consume()
                    }
                    if (!change.pressed) break
                }
                if (startedAtBackEdge && totalDragX >= backThresholdPx && totalDragX > abs(totalDragY)) {
                    section = "map"
                }
            }
        }) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                androidx.compose.material3.TextButton(onClick = { section = "map" }) {
                    Text("← Mapa mental")
                }
                Text(
                    when (section) {
                        "red" -> "Motor y conexiones"
                        "dns" -> "Actividad DNS"
                        "amenazas" -> "Catálogo de amenazas"
                        "reglas" -> "Reglas personalizadas"
                        else -> "Aplicaciones observadas"
                    },
                    Modifier.weight(1f), style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }
            when (section) {
                "red" -> LazyColumn(
                    Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    item { LiveEngineOperations(metrics = tunMetrics, logs = logs, vpnRunning = vpnRunning) }
                }
                "dns" -> LazyColumn(
                    Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    item { LiveMetricSection("DECISIONES DNS", listOf(
                        "Bloqueadas" to tunMetrics.dnsBlocked,
                        "Observadas" to tunMetrics.dnsObserved,
                        "Permitidas" to tunMetrics.dnsAllowed,
                        "Rechazadas" to tunMetrics.dnsRejected,
                        // Transport-specific inbound DNS query counters are not wired in this build.
                    )) }
                    if (logs.isEmpty()) item { Text("Sin eventos DNS registrados.") }
                    items(logs.take(100)) { event ->
                        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp)) {
                            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                Text(event.domain, fontWeight = FontWeight.Bold)
                                Text("${if (event.isBlocked) "BLOQUEADO" else if (event.reason.startsWith("OBSERVE:", true)) "OBSERVADO" else "PERMITIDO"} · ${event.queryType} · ${event.appName}",
                                    style = MaterialTheme.typography.bodySmall)
                                Text(event.reason, style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
                "amenazas" -> LazyColumn(
                    Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    item { Text("Referencias locales para consulta. Su presencia aquí no significa que cada entrada haya sido detectada por el motor.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    items(catalog, key = { "${it.provider}-${it.category}" }) { evidence ->
                        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp)) {
                            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                                Text(evidence.provider, fontWeight = FontWeight.Bold)
                                Text("${categoryLabel(evidence.category)} · ${evidence.platform ?: "Internet"} · ${evidence.relation}",
                                    style = MaterialTheme.typography.bodySmall)
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Button(onClick = { onSetRule(evidence.provider, true) }, Modifier.weight(1f)) { Text("Bloquear") }
                                    Button(onClick = { onSetRule(evidence.provider, false) }, Modifier.weight(1f)) { Text("Permitir") }
                                }
                            }
                        }
                    }
                }
                "reglas" -> LazyColumn(
                    Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    item { Text("Bloqueo personalizado · ${customBlock.size}", fontWeight = FontWeight.Bold) }
                    items(customBlock) { domain ->
                        Card(Modifier.fillMaxWidth()) { Text(domain, Modifier.padding(12.dp)) }
                    }
                    item { Text("Permiso personalizado · ${customAllow.size}", fontWeight = FontWeight.Bold) }
                    items(customAllow) { domain ->
                        Card(Modifier.fillMaxWidth()) { Text(domain, Modifier.padding(12.dp)) }
                    }
                    if (customBlock.isEmpty() && customAllow.isEmpty()) item { Text("Todavía no hay reglas personalizadas.") }
                }
                else -> LazyColumn(
                    Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    item { Text("Aplicaciones identificadas en los eventos DNS visibles: ${observedApps.size}. No representa todas las apps instaladas.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    items(observedApps) { app ->
                        Card(Modifier.fillMaxWidth()) { Text(app, Modifier.padding(12.dp)) }
                    }
                    if (observedApps.isEmpty()) item { Text("No hay aplicaciones identificadas en el historial.") }
                }
            }
        }
    }
}


@Composable
private fun LiveTrafficFlowMap(
    metrics: FirewallDnsTrafficMetrics.Snapshot,
    logs: List<DnsLogEntry>,
    vpnRunning: Boolean,
) {
    val flows = metrics.activeFlows
    Column(Modifier.fillMaxWidth().height(440.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(18.dp)) {
            Column(Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("RECORRIDO DEL TRÁFICO", Modifier.weight(1f), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Text(if (vpnRunning) "EN VIVO" else "DETENIDO", color = if (vpnRunning) Color(0xFF22C55E) else MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                }
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("PILA DE PAQUETES · NO DNS", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
                        FlowStage("ENTRADA", "TUN RX", metrics.tunRxBytes, Modifier.weight(1f))
                        Text("›", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                        FlowStage("INTERFAZ", "NIC RX/TX", "${metrics.nicRxPackets}/${metrics.nicTxPackets}", Modifier.weight(1f))
                        Text("›", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                        FlowStage("RED", "IP RX/TX", "${metrics.ipPacketsReceived}/${metrics.ipPacketsSent}", Modifier.weight(1f))
                    }
                    Text("DNS · RAMA DE RESOLUCIÓN", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
                        FlowStage("CONSULTAS", "DNS", metrics.dnsPolicyDecisions.toString(), Modifier.weight(1f))
                        Text("›", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                        FlowStage("DECISIÓN", "B/O/A", "${metrics.dnsBlocked}/${metrics.dnsObserved}/${metrics.dnsAllowed}", Modifier.weight(1f))
                        Text("›", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                        FlowStage("RESOLVER", "RESPUESTAS", metrics.dnsResponseCallbacks.toString(), Modifier.weight(1f))
                    }
                    Text("Los flujos TCP/UDP/ICMP siguen su propio procesamiento en gVisor; no todos los paquetes IP pasan por el filtro DNS.", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(18.dp)) {
            Column(Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("CONEXIONES ACTIVAS REALES", Modifier.weight(1f), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Text("${flows.size}", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
                }
                if (flows.isEmpty()) {
                    Text("No hay flujos activos registrados en este instante.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    flows.take(4).forEach { flow ->
                        Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(flow.identity.protocol.name, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                                Text(" · ${flow.action}", style = MaterialTheme.typography.labelSmall, color = when (flow.action.uppercase()) { "BLOCK" -> MaterialTheme.colorScheme.error; "OBSERVE" -> MaterialTheme.colorScheme.tertiary; else -> MaterialTheme.colorScheme.primary })
                                Spacer(Modifier.weight(1f))
                                Text("TX ${flow.bytesSent} B · RX ${flow.bytesReceived} B", style = MaterialTheme.typography.labelSmall)
                            }
                            Text("${flow.identity.sourceAddress}:${flow.identity.sourcePort}  →  ${flow.identity.destinationAddress}:${flow.identity.destinationPort}", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                            Text("${flow.identity.appPackage ?: "Aplicación no identificada"} · ${flow.reason}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        if (flow != flows.take(4).last()) androidx.compose.material3.HorizontalDivider()
                    }
                    if (flows.size > 4) Text("Se muestran 4 de ${flows.size}; entra en Motor para consultar la lista completa.", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(18.dp)) {
            Column(Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("ÚLTIMOS EVENTOS DNS", Modifier.weight(1f), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Text("${logs.size} registrados", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                if (logs.isEmpty()) {
                    Text("Sin eventos DNS registrados. No se muestran eventos ficticios.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    logs.take(3).forEach { event ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            val observed = event.reason.startsWith("OBSERVE:", true)
                            Text(when { event.isBlocked -> "BLOQUEADO"; observed -> "OBSERVADO"; else -> "PERMITIDO" }, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold, color = when { event.isBlocked -> MaterialTheme.colorScheme.error; observed -> MaterialTheme.colorScheme.tertiary; else -> MaterialTheme.colorScheme.primary })
                            Text(" · ${event.domain}", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, maxLines = 1)
                            Text(event.timestamp, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun FlowStage(heading: String, subtitle: String, value: String, modifier: Modifier = Modifier) {
    Surface(modifier = modifier, shape = RoundedCornerShape(10.dp), color = MaterialTheme.colorScheme.surfaceVariant) {
        Column(Modifier.padding(horizontal = 4.dp, vertical = 8.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(heading, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
            Text(value, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, maxLines = 1)
            Text(subtitle, style = MaterialTheme.typography.labelSmall, maxLines = 1)
        }
    }
}

@Composable
private fun MindMapAction(label: String, destination: String, symbol: String, onOpen: (String) -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Surface(
            modifier = Modifier.size(54.dp).clickable { onOpen(destination) },
            shape = androidx.compose.foundation.shape.CircleShape,
            color = MaterialTheme.colorScheme.secondaryContainer,
            contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
            shadowElevation = 3.dp
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text(symbol, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            }
        }
        Text(label, style = MaterialTheme.typography.labelSmall, maxLines = 1)
    }
}

@Composable
private fun ThreeDimensionalMindMap(
    nodes: List<MindMapNode>,
    selectedNode: String,
    lastDnsDecisionAtEpochMs: Long,
    lastFlowEventAtEpochMs: Long,
    metrics: FirewallDnsTrafficMetrics.Snapshot,
    activeFlowCount: Long,
    appRoutes: List<SocApplicationRoute>,
    vpnRunning: Boolean,
    onSelectNode: (String) -> Unit
) {
    // Camera orbit animates the 3D architecture, never pretends to be traffic.
    val orbit = rememberInfiniteTransition(label = "soc-3d-orbit")
    val rotation by orbit.animateFloat(
        initialValue = 0f,
        targetValue = (Math.PI * 2.0).toFloat(),
        animationSpec = infiniteRepeatable(tween(24000, easing = LinearEasing), RepeatMode.Restart),
        label = "soc-3d-camera-rotation"
    )
    val latestRotation by rememberUpdatedState(rotation)
    val topologyPulse by orbit.animateFloat(0f, 1f,
        animationSpec = infiniteRepeatable(tween(2200, easing = LinearEasing), RepeatMode.Restart),
        label = "soc-topology-edge-pulse"
    )
    val activePulse by orbit.animateFloat(
        initialValue = .88f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1100), RepeatMode.Reverse),
        label = "soc-active-node-depth-pulse"
    )
    val dnsEventProgress = remember { androidx.compose.animation.core.Animatable(1f) }
    val flowEventProgress = remember { androidx.compose.animation.core.Animatable(1f) }
    androidx.compose.runtime.LaunchedEffect(lastDnsDecisionAtEpochMs, vpnRunning) {
        if (vpnRunning && lastDnsDecisionAtEpochMs > 0L) {
            dnsEventProgress.snapTo(0f)
            dnsEventProgress.animateTo(1f, animationSpec = tween(900, easing = LinearEasing))
        } else dnsEventProgress.snapTo(1f)
    }
    androidx.compose.runtime.LaunchedEffect(lastFlowEventAtEpochMs, vpnRunning) {
        if (vpnRunning && lastFlowEventAtEpochMs > 0L) {
            flowEventProgress.snapTo(0f)
            flowEventProgress.animateTo(1f, animationSpec = tween(1200, easing = LinearEasing))
        } else flowEventProgress.snapTo(1f)
    }
    var selectedAppUid by remember { mutableStateOf<Int?>(null) }
    val background = MaterialTheme.colorScheme.surface
    val lineColor = MaterialTheme.colorScheme.outlineVariant
    val onSurface = MaterialTheme.colorScheme.onSurface
    val density = LocalDensity.current.density
    fun recent(timestamp: Long): Boolean = timestamp > 0L && System.currentTimeMillis() - timestamp in 0L..5000L
    val dnsEventRecent = vpnRunning &&
        lastDnsDecisionAtEpochMs > 0L &&
        System.currentTimeMillis() - lastDnsDecisionAtEpochMs in 0L..2500L
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = background)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("TOPOLOGÍA SOC · FIREWALLDNS", Modifier.weight(1f),
                    style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                Text(
                    if (!vpnRunning) "MOTOR DETENIDO"
                    else if (dnsEventRecent || activeFlowCount > 0L) "ACTIVIDAD DETECTADA"
                    else "EN ESPERA DE EVENTOS",
                    style = MaterialTheme.typography.labelSmall,
                    color = if (vpnRunning) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Canvas(
                Modifier.fillMaxWidth().height(390.dp)
                    .semantics {
                        contentDescription = "Mapa SOC tridimensional. Toca un nodo para consultar su información."
                    }
                    .pointerInput(Unit) {
                        detectTapGestures { tap ->
                            val hit = nodes.map { node ->
                                val point = projectNode(node, size.width.toFloat(), size.height.toFloat(), latestRotation)
                                val dx = point.x - tap.x
                                val dy = point.y - tap.y
                                node to (dx * dx + dy * dy)
                            }.filter { it.second < (48f * density) * (48f * density) }
                                .minByOrNull { it.second }
                            hit?.first?.let { onSelectNode(it.id) }
                        }
                    }
            ) {
                drawIntoCanvas { composeCanvas ->
                    val canvas = composeCanvas.nativeCanvas
                    val w = size.width
                    val h = size.height
                    val centerX = w * .5f
                    val centerY = h * .51f
                    val radius = minOf(w * .43f, h * .43f)
                    val basePaint = Paint(Paint.ANTI_ALIAS_FLAG)
                    val projected = nodes.associateWith {
                        projectNode(it, w, h, rotation)
                    }

                    // Stable 3D depth rings: spatial decoration only, never shown as traffic.
                    for (ring in 0..2) {
                        basePaint.style = Paint.Style.STROKE
                        basePaint.strokeWidth = if (ring == 1) 1.5f else 1f
                        basePaint.color = lineColor.copy(alpha = if (ring == 1) .48f else .22f).toArgb()
                        val oval = RectF(
                            centerX - radius * (1f - ring * .09f),
                            centerY - radius * (.35f + ring * .06f),
                            centerX + radius * (1f - ring * .09f),
                            centerY + radius * (.35f + ring * .06f)
                        )
                        canvas.drawOval(oval, basePaint)
                    }

                    val byId = nodes.associateBy { it.id }
                    architectureEdges.forEachIndexed { edgeIndex, edge ->
                        val from = byId[edge.from] ?: return@forEachIndexed
                        val to = byId[edge.to] ?: return@forEachIndexed
                        val begin = projected.getValue(from)
                        val finish = projected.getValue(to)
                        val isDnsRoute = edge.from == "dns" && edge.to == "decisions"
                        val isFlowRoute = edge.from == "core" && edge.to == "tun"
                        val touchesSelectedNode = edge.from == selectedNode || edge.to == selectedNode
                        val flowEventRecent = vpnRunning && lastFlowEventAtEpochMs > 0L &&
                            System.currentTimeMillis() - lastFlowEventAtEpochMs in 0L..5000L
                        val routeActive = vpnRunning && (
                            (isDnsRoute && dnsEventRecent) ||
                            (isFlowRoute && activeFlowCount > 0L) ||
                            (edge.from == "tun" && activeFlowCount > 0L)
                        )
                        basePaint.style = Paint.Style.STROKE
                        basePaint.strokeWidth = when {
                            touchesSelectedNode -> 2.6f
                            routeActive -> 3f
                            else -> 1.5f
                        }
                        basePaint.color = when {
                            touchesSelectedNode -> to.tint.copy(alpha = .72f).toArgb()
                            routeActive -> to.tint.copy(alpha = .9f).toArgb()
                            else -> to.tint.copy(alpha = .24f).toArgb()
                        }
                        canvas.drawLine(begin.x, begin.y, finish.x, finish.y, basePaint)

                        // Continuous, subtle topology pulse: visual architecture, not packet traffic.
                        val topologyProgress = (topologyPulse + edgeIndex * .173f) % 1f
                        val topologyX = begin.x + (finish.x - begin.x) * topologyProgress
                        val topologyY = begin.y + (finish.y - begin.y) * topologyProgress
                        basePaint.style = Paint.Style.FILL
                        basePaint.color = Color(0xFF8AA8C8).copy(alpha = .62f).toArgb()
                        canvas.drawCircle(topologyX, topologyY, 2.1f * density, basePaint)

                        // This short-lived marker corresponds to the timestamped DNS decision event.
                        // It is not a packet and never loops when the engine is idle.
                        val eventProgress = when {
                            isDnsRoute && dnsEventRecent -> dnsEventProgress.value
                            isFlowRoute && flowEventRecent -> flowEventProgress.value
                            else -> 1f
                        }
                        val eventIsVisible = (isDnsRoute && dnsEventRecent) ||
                            (isFlowRoute && flowEventRecent)
                        if (eventIsVisible && eventProgress < 1f) {
                            val px = begin.x + (finish.x - begin.x) * eventProgress
                            val py = begin.y + (finish.y - begin.y) * eventProgress
                            val eventTint = if (isDnsRoute) Color(0xFFFF667D) else Color(0xFF42D9FF)
                            basePaint.style = Paint.Style.FILL
                            basePaint.color = eventTint.toArgb()
                            basePaint.setShadowLayer(14f, 0f, 0f, eventTint.toArgb())
                            canvas.drawCircle(px, py, 4.5f * density, basePaint)
                            basePaint.clearShadowLayer()
                            canvas.drawCircle(px, py, 1.7f * density, android.graphics.Paint().apply {
                                color = android.graphics.Color.WHITE
                                isAntiAlias = true
                            })
                        }
                    }

                    nodes.sortedBy { projected.getValue(it).y }.forEach { node ->
                        val point = projected.getValue(node)
                        val depth = (point.zDepth + 1f) / 2f
                        val nodeRadius = (if (node.id == "core") 17f else 11f) * (.78f + depth * .38f)
                        val isSelected = node.id == selectedNode
                        val nodeActive = vpnRunning && when (node.id) {
                            "core", "tun" -> true
                            "firestack" -> metrics.firestackActive > 0L
                            "nic" -> activeFlowCount > 0L || recent(metrics.nicChangeObservedAtEpochMs)
                            "ip" -> activeFlowCount > 0L || recent(metrics.ipChangeObservedAtEpochMs)
                            "tcp" -> metrics.activeFlows.any { it.identity.protocol.name == "TCP" } || recent(metrics.tcpChangeObservedAtEpochMs)
                            "udp" -> metrics.activeFlows.any { it.identity.protocol.name == "UDP" } || recent(metrics.udpChangeObservedAtEpochMs)
                            "icmp" -> metrics.activeFlows.any { it.identity.protocol.name == "ICMP" } || recent(metrics.icmpChangeObservedAtEpochMs)
                            "fwd" -> recent(metrics.forwardChangeObservedAtEpochMs)
                            "dns", "decisions" -> dnsEventRecent
                            "apps" -> activeFlowCount > 0L
                            else -> false
                        }
                        basePaint.style = Paint.Style.FILL
                        basePaint.color = node.tint.copy(alpha = if (nodeActive) .22f else .055f).toArgb()
                        canvas.drawCircle(
                            point.x, point.y,
                            nodeRadius * (if (nodeActive) 2.8f else 1.55f) * activePulse,
                            basePaint
                        )
                        basePaint.color = node.tint.copy(alpha = if (nodeActive) .34f else .12f).toArgb()
                        canvas.drawCircle(
                            point.x, point.y,
                            nodeRadius * (if (nodeActive) 1.65f else 1.18f) * activePulse,
                            basePaint
                        )
                        basePaint.color = node.tint.copy(alpha = if (nodeActive) 1f else .14f).toArgb()
                        if (nodeActive) basePaint.setShadowLayer(12f, 0f, 4f, node.tint.copy(alpha = .75f).toArgb())
                        canvas.drawCircle(point.x, point.y, nodeRadius * if (isSelected) 1.18f else 1f, basePaint)
                        basePaint.clearShadowLayer()
                        basePaint.color = if (nodeActive) android.graphics.Color.WHITE else android.graphics.Color.GRAY
                        canvas.drawCircle(point.x, point.y, nodeRadius * .34f, basePaint)

                        basePaint.color = if (isSelected) node.tint.toArgb() else onSurface.toArgb()
                        basePaint.textAlign = Paint.Align.CENTER
                        basePaint.typeface = android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.BOLD)
                        basePaint.textSize = 10.5f * density
                        canvas.drawText(node.label, point.x, point.y + nodeRadius + 15f * density, basePaint)
                        basePaint.textSize = 8f * density
                        basePaint.typeface = android.graphics.Typeface.create("sans-serif", android.graphics.Typeface.NORMAL)
                        basePaint.color = onSurface.copy(alpha = .82f).toArgb()
                        canvas.drawText(node.value.take(25), point.x, point.y + nodeRadius + 26f * density, basePaint)
                    }
                }
            }
            NodeRouteInspector(
                nodes = nodes,
                selectedNode = selectedNode,
                appRoutes = appRoutes,
                selectedAppUid = selectedAppUid,
                onAppSelected = { selectedAppUid = it }
            )
            Text(
                "La cámara mantiene una órbita 3D. Los pulsos tenues recorren todas las conexiones como guía visual de topología; los marcadores de eventos representan actividad observada, no paquetes individuales.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun NodeRouteInspector(
    nodes: List<MindMapNode>,
    selectedNode: String,
    appRoutes: List<SocApplicationRoute>,
    selectedAppUid: Int?,
    onAppSelected: (Int) -> Unit,
) {
    val byId = nodes.associateBy { it.id }
    val selected = byId[selectedNode] ?: return
    val incoming = architectureEdges.filter { it.to == selectedNode }.mapNotNull { byId[it.from] }
    val outgoing = architectureEdges.filter { it.from == selectedNode }.mapNotNull { byId[it.to] }
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(11.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("RECORRIDOS DEL NODO · ${selected.label}", style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold)
            Text(selected.hint, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("ENTRADA", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
            Text(incoming.joinToString("  ·  ") { it.label }.ifBlank { "Sin conexiones de entrada definidas" },
                style = MaterialTheme.typography.bodySmall)
            Text("SALIDA", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
            Text(outgoing.joinToString("  ·  ") { it.label }.ifBlank { "Sin conexiones de salida definidas" },
                style = MaterialTheme.typography.bodySmall)
            if (selectedNode == "apps") {
                Text("APLICACIÓN / UID", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                if (appRoutes.isEmpty()) {
                    Text("No hay aplicaciones con UID identificable en los eventos DNS o flujos activos.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    appRoutes.take(8).chunked(2).forEach { group ->
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                            group.forEach { app ->
                                FilterChip(
                                    selected = selectedAppUid == app.uid || (selectedAppUid == null && appRoutes.firstOrNull()?.uid == app.uid),
                                    onClick = { onAppSelected(app.uid) },
                                    label = { Text(app.label.take(15) + " · " + app.uid, style = MaterialTheme.typography.labelSmall) }
                                )
                            }
                        }
                    }
                    val selectedApp = appRoutes.firstOrNull { it.uid == selectedAppUid } ?: appRoutes.firstOrNull()
                    if (selectedApp != null) {
                        Text(
                            "${selectedApp.label} · UID ${selectedApp.uid} · DNS ${selectedApp.dnsEvents} · FLUJOS ACTIVOS ${selectedApp.flows.size}",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.SemiBold
                        )
                        if (selectedApp.flows.isEmpty()) {
                            Text("Sin flujos activos identificados para esta aplicación en este instante.",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        } else {
                            selectedApp.flows.take(4).forEach { flow ->
                                Text(
                                    "${flow.identity.protocol.name} · ${flow.identity.destinationAddress}:${flow.identity.destinationPort} · TX ${flow.bytesSent} B / RX ${flow.bytesReceived} B",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
                Text("La aplicación se identifica por UID. El recorrido muestra la topología de red; los flujos listados son observaciones reales independientes.",
                    style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(
                "La topología completa se muestra mediante las conexiones de entrada y salida de cada nodo. La actividad resaltada depende de eventos observados, no de una ruta seleccionada manualmente.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                "Las conexiones de entrada y salida describen la topología. El resaltado visual de actividad depende de eventos observados y no confirma por sí solo paquetes individuales.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private fun SocArchitectureLayers(
    observedApps: Int,
    metrics: FirewallDnsTrafficMetrics.Snapshot,
) {
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("ARQUITECTURA POR CAPAS", style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                SocLayerTile("DISPOSITIVO", "Apps Android / UID", observedApps.toString(),
                    Color(0xFF58D6B0), Modifier.weight(1f))
                SocLayerTile("CAPTURA", "TUN · Firestack",
                    if (metrics.firestackActive > 0L) "ACTIVO" else "N/D",
                    Color(0xFF4EA5FF), Modifier.weight(1f))
                SocLayerTile("RED", "IP · TCP · UDP · ICMP", metrics.flowsActive.toString(),
                    Color(0xFF78A8FF), Modifier.weight(1f))
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                SocLayerTile("PROTECCIÓN", "DNS · reglas · amenazas",
                    metrics.dnsPolicyDecisions.toString(), Color(0xFFFF667D), Modifier.weight(1f))
                SocLayerTile("RESOLUCIÓN / SOC", "Flujos · actualizaciones resolvers",
                    metrics.flowsActive.toString(), Color(0xFF68D9A5), Modifier.weight(1f))
            }
            Text("Los valores muestran métricas disponibles; no representan inventario completo de aplicaciones ni paquetes individuales.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun SocLayerTile(
    title: String,
    detail: String,
    value: String,
    tint: Color,
    modifier: Modifier = Modifier,
) {
    Surface(modifier, shape = RoundedCornerShape(11.dp), color = tint.copy(alpha = .12f)) {
        Column(Modifier.fillMaxWidth().padding(8.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(title, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold,
                color = tint, maxLines = 1)
            Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold,
                maxLines = 1)
            Text(detail, style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2)
        }
    }
}

@Composable
private fun SocHeader(
    vpnRunning: Boolean,
    metrics: FirewallDnsTrafficMetrics.Snapshot,
) {
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (vpnRunning) Color(0xFF102D2B) else MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text("SECURITY OPERATIONS CENTER", style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold, color = if (vpnRunning) Color(0xFF8BE8C5) else MaterialTheme.colorScheme.onSurfaceVariant)
                Text("FirewallDNS · Túnel de red", style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold)
                Text(
                    if (vpnRunning) "Protección activa · Firestack ${if (metrics.firestackActive > 0) "conectado" else "sin confirmación"}"
                    else "Protección detenida · telemetría histórica",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Surface(
                shape = RoundedCornerShape(50),
                color = if (vpnRunning) Color(0xFF176B52) else MaterialTheme.colorScheme.surface
            ) {
                Text(if (vpnRunning) "● EN LÍNEA" else "○ OFFLINE",
                    Modifier.padding(horizontal = 11.dp, vertical = 8.dp),
                    style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun SocKpiGrid(metrics: FirewallDnsTrafficMetrics.Snapshot) {
    Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
        Text("RESUMEN OPERATIVO", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
            SocKpi("PAQUETES IP RX", metrics.ipPacketsReceived.toString(), "Contador agregado IPv4 + IPv6", Color(0xFF2776B8), Modifier.weight(1f))
            SocKpi("FLUJOS ACTIVOS", metrics.flowsActive.toString(), "Abiertos ${metrics.flowsOpened}", Color(0xFF247A62), Modifier.weight(1f))
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
            SocKpi("DNS BLOQUEADOS", metrics.dnsBlocked.toString(), "Observados ${metrics.dnsObserved}", Color(0xFF9B454F), Modifier.weight(1f))
            SocKpi("DNS PERMITIDOS", metrics.dnsAllowed.toString(), "Rechazados ${metrics.dnsRejected}", Color(0xFF6551A1), Modifier.weight(1f))
        }
    }
}

@Composable
private fun SocKpi(
    label: String,
    value: String,
    detail: String,
    tint: Color,
    modifier: Modifier = Modifier,
) {
    Card(modifier, shape = RoundedCornerShape(15.dp),
        colors = CardDefaults.cardColors(containerColor = tint.copy(alpha = .16f))) {
        Column(Modifier.fillMaxWidth().padding(11.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(label, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface)
            Text(detail, style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun SocAppDnsActivity(
    logs: List<DnsLogEntry>,
    flows: List<com.firewalldns.engine.monitor.ActiveFlowSnapshot>,
) {
    data class UidActivity(
        val uid: Int,
        val appName: String,
        val blocked: Int,
        val observed: Int,
        val allowed: Int,
        val total: Int,
        val activeConnections: Int,
        val bytesSent: Long,
        val bytesReceived: Long,
    )
    val logsByUid = logs.filter { it.uid >= 0 }.groupBy { it.uid }
    val flowsByUid = flows.filter { it.identity.appUid != null }.groupBy { it.identity.appUid!! }
    val knownUids = (logsByUid.keys + flowsByUid.keys).distinct()
    val appRows = knownUids.map { uid ->
        val events = logsByUid[uid].orEmpty()
        val appFlows = flowsByUid[uid].orEmpty()
        UidActivity(
            uid = uid,
            appName = events.firstOrNull { it.appName.isNotBlank() }?.appName
                ?: appFlows.firstOrNull { !it.identity.appPackage.isNullOrBlank() }?.identity?.appPackage
                ?: "Aplicación sin nombre resuelto",
            blocked = events.count { it.decisionAction == "BLOCK" || it.isBlocked },
            observed = events.count { it.decisionAction == "OBSERVE" },
            allowed = events.count { it.decisionAction != "OBSERVE" && it.decisionAction != "BLOCK" && !it.isBlocked },
            total = events.size,
            activeConnections = appFlows.size,
            bytesSent = appFlows.sumOf { it.bytesSent },
            bytesReceived = appFlows.sumOf { it.bytesReceived },
        )
    }.sortedWith(compareByDescending<UidActivity> { it.activeConnections }.thenByDescending { it.total })
        .take(8)
    val unknownDnsCount = logs.count { it.uid < 0 }
    val unknownFlows = flows.filter { it.identity.appUid == null }
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("ACTIVIDAD POR UID DE ANDROID", style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold)
            if (appRows.isEmpty() && unknownDnsCount == 0 && unknownFlows.isEmpty()) {
                Text("Sin consultas DNS ni conexiones activas registradas.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            } else {
                appRows.forEach { row ->
                    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(row.appName, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold, maxLines = 1)
                            Text("UID ${row.uid}", style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Text(
                            "DNS · BLOQ. ${row.blocked} · OBS. ${row.observed} · PERM. ${row.allowed} · TOTAL ${row.total}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            "Conexiones activas ${row.activeConnections} · TX ${row.bytesSent} B · RX ${row.bytesReceived} B",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        if (row.total > 0) {
                            androidx.compose.material3.LinearProgressIndicator(
                                progress = { row.blocked.toFloat() / row.total },
                                modifier = Modifier.fillMaxWidth(),
                                color = MaterialTheme.colorScheme.error,
                                trackColor = MaterialTheme.colorScheme.surfaceVariant
                            )
                        }
                    }
                }
                if (unknownDnsCount > 0 || unknownFlows.isNotEmpty()) {
                    androidx.compose.material3.HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    Text(
                        "SIN UID IDENTIFICABLE · DNS $unknownDnsCount · CONEXIONES ${unknownFlows.size}",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Text(
                "DNS y flujos se atribuyen usando el UID real que informa Firestack/Android. Un UID puede compartir varios paquetes. Los datos sin UID no se asignan a ninguna aplicación.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun SocPolicyDiagnostics(metrics: FirewallDnsTrafficMetrics.Snapshot) {
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("DIAGNÓSTICO DE POLÍTICA DNS", Modifier.weight(1f),
                    style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Text(metrics.policyInstallStatus,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = if (metrics.policyInstallStatus == "APLICADAS") Color(0xFF35C995) else MaterialTheme.colorScheme.error)
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Column(Modifier.weight(1f)) {
                    Text("REGLAS EN MOTOR", style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(metrics.policyRuleCount.toString(), style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold)
                }
                Column(Modifier.weight(1f)) {
                    Text("REVISIÓN ACTIVA", style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(metrics.policyRevision.toString(), style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold)
                }
                Column(Modifier.weight(1f)) {
                    Text("FALLOS AL APLICAR", style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(metrics.policyInstallFailures.toString(), style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        color = if (metrics.policyInstallFailures > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
                }
            }
            androidx.compose.material3.HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Text("ÚLTIMA DECISIÓN DNS", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
            if (metrics.lastDnsDomain.isBlank()) {
                Text("Aún no hay una consulta DNS registrada por el motor.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            } else {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(metrics.lastDnsDomain, Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                    Text(metrics.lastDnsAction,
                        style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold,
                        color = when (metrics.lastDnsAction) {
                            "BLOCK" -> MaterialTheme.colorScheme.error
                            "OBSERVE" -> MaterialTheme.colorScheme.tertiary
                            else -> MaterialTheme.colorScheme.primary
                        })
                }
                Text(metrics.lastDnsReason, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text("Este panel refleja reglas instaladas en el runtime y decisiones observadas en callbacks DNS; no cuenta solo las listas guardadas.",
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun SocTunnelPath(
    metrics: FirewallDnsTrafficMetrics.Snapshot,
    vpnRunning: Boolean,
) {
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("RECORRIDO DEL TÚNEL", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Text("Contadores acumulados reportados por el servicio; no representan paquetes simultáneos.",
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            val stages = listOf(
                Triple("ENTRADA TUN", "N/D", "Firestack no expone contador de paquetes TUN en esta API"),
                Triple("CLASIFICACIÓN IP", "N/D", "No hay callbacks de conteo IPv4/IPv6 conectados en esta compilación"),
                Triple("POLÍTICA DNS", "${metrics.dnsBlocked + metrics.dnsObserved + metrics.dnsAllowed}", "Bloquear · observar · permitir"),
                Triple("FLUJOS", "${metrics.flowsOpened}", "Conexiones abiertas por FlowMonitor"),
                Triple("SALIDA TUN", "N/D", "Firestack no expone contador de paquetes TUN en esta API")
            )
            stages.forEachIndexed { index, stage ->
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Surface(shape = RoundedCornerShape(9.dp),
                        color = if (vpnRunning) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant) {
                        Text("${index + 1}", Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
                            fontWeight = FontWeight.Bold)
                    }
                    Column(Modifier.weight(1f).padding(start = 9.dp), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                        Text(stage.first, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                        Text(stage.third, style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Text(stage.second.toString(), style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold)
                }
                if (index != stages.lastIndex) {
                    androidx.compose.material3.HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = .5f))
                }
            }
            Text("La etapa DNS contabiliza solo las consultas DNS; el resto del tráfico IP continúa por los flujos gestionados por el motor.",
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun LiveMapTelemetry(
    metrics: FirewallDnsTrafficMetrics.Snapshot,
    logs: List<DnsLogEntry>,
    vpnRunning: Boolean,
) {
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                MapStatPill("TUN", "N/D", Color(0xFF1C806B))
                MapStatPill("DNS", metrics.dnsPolicyDecisions.toString(), Color(0xFF315FA8))
                MapStatPill("ACTIVOS", metrics.flowsActive.toString(), Color(0xFF7655A8))
                MapStatPill("VPN", if (vpnRunning) "ON" else "OFF",
                    if (vpnRunning) Color(0xFF1C806B) else MaterialTheme.colorScheme.surfaceVariant)
            }
            val latest = logs.firstOrNull()
            Text(
                latest?.let {
                    "ÚLTIMO DNS · ${it.domain} · ${when {
                        it.isBlocked -> "BLOQUEADO"
                        it.reason.startsWith("OBSERVE:", true) -> "OBSERVADO"
                        else -> "PERMITIDO"
                    }}"
                } ?: "ÚLTIMO DNS · Sin eventos registrados",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1
            )
        }
    }
}

private data class ProjectedNode(val x: Float, val y: Float, val zDepth: Float)

private fun projectNode(node: MindMapNode, width: Float, height: Float, rotation: Float): ProjectedNode {
    val cosY = cos(rotation)
    val sinY = sin(rotation)
    val rotatedX = node.x * cosY - node.z * sinY
    val rotatedZ = node.x * sinY + node.z * cosY
    val tilt = -.20f
    val rotatedY = node.y * cos(tilt) - rotatedZ * sin(tilt)
    val depth = node.y * sin(tilt) + rotatedZ * cos(tilt)
    val perspective = 1f / (1f + depth * .20f)
    return ProjectedNode(
        width * .5f + rotatedX * width * .34f * perspective,
        height * .5f + rotatedY * height * .32f * perspective,
        depth
    )
}

@Composable
private fun MapStatPill(label: String, value: String, color: Color) {
    Surface(shape = RoundedCornerShape(10.dp), color = color) {
        Row(Modifier.padding(horizontal = 9.dp, vertical = 7.dp),
            horizontalArrangement = Arrangement.spacedBy(5.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(label, style = MaterialTheme.typography.labelSmall)
            Text(value, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
        }
    }
}


@Composable
private fun NodePill(label: String) {
    Surface(shape = RoundedCornerShape(8.dp), color = MaterialTheme.colorScheme.surfaceVariant) {
        Text(label, Modifier.padding(horizontal = 7.dp, vertical = 5.dp), style = MaterialTheme.typography.labelSmall)
    }
}

private fun categoryLabel(category: ThreatKnowledgeGraph.Category): String = when (category) {
    ThreatKnowledgeGraph.Category.ADVERTISING -> "Publicidad"
    ThreatKnowledgeGraph.Category.TRACKING -> "Rastreo"
    ThreatKnowledgeGraph.Category.ANALYTICS -> "Analítica"
}


@Composable
private fun LiveEngineOperations(
    metrics: FirewallDnsTrafficMetrics.Snapshot,
    logs: List<DnsLogEntry>,
    vpnRunning: Boolean,
) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text("ACTIVIDAD OPERATIVA EN TIEMPO REAL", style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold)
            Text(
                if (vpnRunning) "Flujos, decisiones DNS y estadísticas nativas de Firestack/gVisor proceden del mismo túnel de producción. Los contadores nativos son snapshots y Firestack puede reutilizarlos durante hasta 30 segundos."
                else "Servicio detenido. Se muestran los últimos contadores disponibles; no se simula actividad.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        LiveMetricSection("TUN / NIC · INTERFAZ DEL MOTOR", listOf(
            "Paquetes NIC RX" to metrics.nicRxPackets,
            "Paquetes NIC TX" to metrics.nicTxPackets,
            "Paquetes NIC inválidos" to metrics.tunInvalidPackets,
            "Protocolos L3 desconocidos" to metrics.tunUnknownL3Packets,
            "Protocolos L4 desconocidos" to metrics.tunUnknownL4Packets,
            "Descartes NIC" to metrics.tunDrops,
        ), "TUN endpoint · bytes leídos hacia gVisor: ${metrics.tunRxBytes} · bytes escritos hacia Android: ${metrics.tunTxBytes}. NIC bytes RX: ${metrics.nicRxBytes} · TX: ${metrics.nicTxBytes}.")
        LiveMetricSection("IP · PAQUETES Y ERRORES", listOf(
            "Paquetes IP recibidos" to metrics.ipPacketsReceived,
            "Paquetes IP enviados" to metrics.ipPacketsSent,
            "Paquetes IP inválidos" to metrics.ipInvalidPackets,
            "Errores de recepción IP" to metrics.ipReceiveErrors,
            "Errores de envío IP" to metrics.ipSendErrors,
            "Descartes de reenvío" to metrics.ipForwardDrops,
            "Errores de reenvío" to metrics.ipForwardErrors,
        ), "Contadores de la capa IP de gVisor; no se suman con los contadores NIC/TUN.")
        LiveMetricSection("TCP · SEGMENTOS Y CONEXIONES", listOf(
            "Segmentos recibidos" to metrics.tcpSegmentsReceived,
            "Segmentos enviados" to metrics.tcpSegmentsSent,
            "Conexiones establecidas actuales" to metrics.tcpEstablished,
            "Fallos al conectar" to metrics.tcpConnectFailures,
            "Retransmisiones" to metrics.tcpRetransmits,
            "Timeouts" to metrics.tcpTimeouts,
            "Descartes TCP" to metrics.tcpDrops,
        ))
        LiveMetricSection("UDP · DATAGRAMAS", listOf(
            "Datagramas recibidos" to metrics.udpPacketsReceived,
            "Datagramas enviados" to metrics.udpPacketsSent,
            "Errores de recepción / checksum / puerto" to metrics.udpReceiveErrors,
            "Descartes UDP" to metrics.udpDrops,
        ), "No se expone ErrSnd: la versión Firestack revisada asigna incorrectamente ese campo.")
        LiveMetricSection("ICMP · IPv4 / IPv6", listOf(
            "ICMPv4 · mensajes recibidos" to metrics.icmpV4Received,
            "ICMPv4 · mensajes enviados" to metrics.icmpV4Sent,
            "ICMPv6 · mensajes recibidos" to metrics.icmpV6Received,
            "ICMPv6 · mensajes enviados" to metrics.icmpV6Sent,
        ), "Los contadores ICMP sí están separados por familia IP. Los contadores TCP/UDP/IP generales no ofrecen esa separación.")
        LiveMetricSection("INSPECCIÓN DNS Y DECISIONES", listOf(
            "Evaluaciones DNS" to metrics.dnsPolicyDecisions,
            "Bloqueadas" to metrics.dnsBlocked,
            "Observadas" to metrics.dnsObserved,
            "Permitidas" to metrics.dnsAllowed,
            "Rechazadas por política/parser DNS" to metrics.dnsRejected,
            "Aciertos de caché de política" to metrics.cacheHits,
            "Fallos de caché de política" to metrics.cacheMisses,
            "Eventos de telemetría descartados" to metrics.engineEventsDropped,
            "Eventos pendientes en cola" to metrics.engineQueuedEvents,
        ))
        LiveMetricSection("RESOLUCIÓN Y RED FÍSICA", listOf(
            "Cambios de lista de resolvers" to metrics.upstreamResolverRefreshes,
        ), metrics.upstreamResolvers.ifBlank { "Resolvers: sin datos" })
        LiveMetricSection("CONEXIONES Y FLUJOS FIRESTACK", listOf(
            "Flujos activos" to metrics.flowsActive,
            "Flujos abiertos" to metrics.flowsOpened,
            "Flujos cerrados" to metrics.flowsClosed,
            "Flujos bloqueados" to metrics.flowsBlocked,
            "Bytes enviados" to metrics.flowBytesSent,
            "Bytes recibidos" to metrics.flowBytesReceived,
            "Rechazos por capacidad" to metrics.flowCapacityRejected,
            "Firestack activo (0/1)" to metrics.firestackActive,
        ), "Monitor FlowConnectionMonitor; el límite configurado es 4,096 flujos simultáneos.")
        // Count a flow only when both endpoints agree on the address family.
        // Mixed or unparsable endpoints remain unknown instead of being double-counted.
        val ipv4Flows = metrics.activeFlows.filter { flow ->
            flow.identity.sourceAddress.contains('.') && flow.identity.destinationAddress.contains('.')
        }
        val ipv6Flows = metrics.activeFlows.filter { flow ->
            flow.identity.sourceAddress.contains(':') && flow.identity.destinationAddress.contains(':')
        }
        val unknownFamilyFlows = metrics.activeFlows.size - ipv4Flows.size - ipv6Flows.size
        LiveMetricSection("FAMILIA IP · FLUJOS ACTIVOS OBSERVADOS", listOf(
            "Flujos IPv4 activos" to ipv4Flows.size.toLong(),
            "Bytes TX IPv4 en flujos activos" to ipv4Flows.sumOf { it.bytesSent },
            "Bytes RX IPv4 en flujos activos" to ipv4Flows.sumOf { it.bytesReceived },
            "Flujos IPv6 activos" to ipv6Flows.size.toLong(),
            "Bytes TX IPv6 en flujos activos" to ipv6Flows.sumOf { it.bytesSent },
            "Bytes RX IPv6 en flujos activos" to ipv6Flows.sumOf { it.bytesReceived },
            "Flujos sin familia identificable" to unknownFamilyFlows.coerceAtLeast(0).toLong(),
        ), "Clasificación orientativa de los extremos de cada flujo activo; no cuenta paquetes IP. Los paquetes con extremos mixtos o no reconocidos quedan como familia no identificable. Los contadores nativos TUN/IP no están disponibles.")
        LiveMetricSection("COLA DE EVENTOS DEL MOTOR", listOf(
            "Eventos actualmente pendientes" to metrics.engineQueuedEvents,
            "Eventos descartados por cola llena" to metrics.engineEventsDropped,
            "Capacidad configurada de la cola" to 512L,
        ), "Cola acotada de telemetría EngineMonitor (capacidad 512); no es una cola de paquetes TUN. El contador de ocupación es una instantánea.")
        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text("TRANSPORTE DNS UPSTREAM · SOCKETS", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Text("Protect UDP/TCP por separado: N/D. El cliente AndroidDnsSocketProtector no está conectado al flujo productivo Firestack.")
            Text("El resultado agregado de VpnService.protect() para sockets Firestack aparece en la sección de protección de sockets.")
        }
        LiveMetricSection("RESÚMENES DE RESPUESTA DNS FIRESTACK", listOf(
            "Callbacks de respuesta observados" to metrics.dnsResponseCallbacks,
            "Estado Complete" to metrics.dnsResponseComplete,
            "Otros estados" to metrics.dnsResponseOtherStatus,
            "Respuestas desde caché" to metrics.dnsResponseCached,
            "Muestras de latencia" to metrics.dnsResponseLatencySamples,
            "Latencia media (ms)" to if (metrics.dnsResponseLatencySamples > 0L)
                metrics.dnsResponseLatencyMsTotal / metrics.dnsResponseLatencySamples else 0L,
            "Último código de estado (-1 = sin dato)" to metrics.dnsResponseLastStatus,
        ), "Callback real OnResponse de Firestack. Puede emitirse más de una vez por consulta; cuenta resúmenes, no consultas únicas ni intentos por socket upstream.")
        LiveActiveFlows(metrics.activeFlows)
        LiveMetricSection("PROTECCIÓN DE SOCKETS FIRESTACK", listOf(
            "Protección socket correcta" to metrics.firestackProtectSuccess,
            "Fallos protección socket" to metrics.firestackProtectFailure,
            "Vinculación a red correcta" to metrics.firestackBindSuccess,
            "Fallos vinculación a red" to metrics.firestackBindFailure,
        ))
        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(15.dp)) {
            Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("SECUENCIA DNS REGISTRADA", style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold)
                if (logs.isEmpty()) {
                    Text("Sin eventos DNS registrados. No se generan eventos de demostración.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    logs.take(12).forEach { event ->
                        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    when {
                                        event.isBlocked -> "BLOQUEADO"
                                        event.reason.startsWith("OBSERVE:", true) -> "OBSERVADO"
                                        else -> "PERMITIDO"
                                    },
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = when {
                                        event.isBlocked -> MaterialTheme.colorScheme.error
                                        event.reason.startsWith("OBSERVE:", true) -> MaterialTheme.colorScheme.tertiary
                                        else -> MaterialTheme.colorScheme.primary
                                    }
                                )
                                Text(" · ${event.queryType}", style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            Text(event.domain, style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold)
                            Text("${event.appName} · ${event.reason}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                            if (event.timestamp.isNotBlank()) {
                                Text(event.timestamp, style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                        if (event != logs.take(12).last()) {
                            androidx.compose.material3.HorizontalDivider()
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LiveMetricSection(
    title: String,
    values: List<Pair<String, Long>>,
    subtitle: String? = null,
) {
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(15.dp)) {
        Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            if (!subtitle.isNullOrBlank()) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            values.forEach { (label, value) ->
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                    Text(value.toString(), style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}


@Composable
private fun LiveActiveFlows(flows: List<com.firewalldns.engine.monitor.ActiveFlowSnapshot>) {
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(15.dp)) {
        Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("CONEXIONES ACTIVAS IDENTIFICADAS", Modifier.weight(1f),
                    style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Text(flows.size.toString(), style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
            }
            Text("Instantánea real del monitor Firestack; se actualiza aproximadamente cada segundo. Se muestran hasta 30 conexiones.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (flows.isEmpty()) {
                Text("No hay flujos activos registrados en este instante.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            } else {
                flows.take(30).forEach { flow ->
                    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(flow.identity.protocol.name, style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold)
                            Text(" · ${flow.action}", style = MaterialTheme.typography.labelSmall,
                                color = when (flow.action.uppercase()) {
                                    "BLOCK" -> MaterialTheme.colorScheme.error
                                    "OBSERVE" -> MaterialTheme.colorScheme.tertiary
                                    else -> MaterialTheme.colorScheme.primary
                                })
                        }
                        Text(
                            "${flow.identity.sourceAddress}:${flow.identity.sourcePort}  →  ${flow.identity.destinationAddress}:${flow.identity.destinationPort}",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.SemiBold
                        )
                        Text(
                            "UID ${flow.identity.appUid ?: "NO IDENTIFICABLE"} · ${flow.identity.appPackage ?: "Aplicación no identificada"} · TX ${flow.bytesSent} B · RX ${flow.bytesReceived} B",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(flow.reason, style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    if (flow != flows.take(30).last()) {
                        androidx.compose.material3.HorizontalDivider()
                    }
                }
            }
        }
    }
}
