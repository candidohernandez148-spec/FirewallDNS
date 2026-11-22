package com.firewall.dns.ui.screens

import android.graphics.Paint
import android.graphics.RectF
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.graphics.toArgb
import com.firewall.dns.domain.engine.ThreatKnowledgeGraph
import com.firewall.dns.domain.model.DnsLogEntry
import com.firewall.dns.service.FirewallDnsTrafficMetrics
import kotlin.math.cos
import kotlin.math.sin

private data class MindMapEdge(val from: String, val to: String)

private val architectureEdges = listOf(
    MindMapEdge("core", "tun"),
    MindMapEdge("tun", "dns"),
    MindMapEdge("dns", "decisions"),
    MindMapEdge("core", "threats"),
    MindMapEdge("rules", "decisions"),
    MindMapEdge("apps", "decisions"),
    MindMapEdge("decisions", "upstream"),
    MindMapEdge("decisions", "tun")
)

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
) {
    var section by remember { mutableStateOf("map") }
    val catalog = remember { ThreatKnowledgeGraph.catalogSnapshot() }
    val observedApps = logs.map { it.appName }
        .filter { it.isNotBlank() && it != "Sistema / DNS" }.distinct()
    val nodes = remember(logs, customBlock, customAllow, tunMetrics, vpnRunning,
        smartModeEnabled, observationModeEnabled, catalog) {
        listOf(
            MindMapNode("core", "FIREWALLDNS", "Servicio VPN", if (vpnRunning) "ACTIVO" else "DETENIDO",
                0f, 0f, 0f, Color(0xFF42D9FF)),
            MindMapNode("tun", "MOTOR DE RED", "Firestack/gVisor", tunMetrics.flowsActive.toString(),
                -0.88f, -0.55f, -0.18f, Color(0xFF58D6B0)),
            MindMapNode("dns", "DNS", "Consultas evaluadas",
                (tunMetrics.dnsBlocked + tunMetrics.dnsObserved + tunMetrics.dnsAllowed).toString(),
                0.82f, -0.63f, 0.20f, Color(0xFF78A8FF)),
            MindMapNode("decisions", "DECISIONES", "Bloquear / observar / permitir",
                "${tunMetrics.dnsBlocked} / ${tunMetrics.dnsObserved} / ${tunMetrics.dnsAllowed}",
                -0.96f, 0.48f, 0.24f, Color(0xFFFF667D)),
            MindMapNode("threats", "AMENAZAS", "Catálogo local de referencia",
                catalog.size.toString(), 0.96f, 0.46f, -0.22f, Color(0xFFFFB454)),
            MindMapNode("rules", "REGLAS", "Reglas personalizadas",
                "${customBlock.size} bloqueo · ${customAllow.size} permiso",
                -0.18f, 0.94f, -0.42f, Color(0xFFB69CFF)),
            MindMapNode("upstream", "RESOLVERS", "DNS de red física",
                tunMetrics.upstreamResolverRefreshes.toString(),
                0.20f, -0.98f, 0.42f, Color(0xFF68D9A5)),
            MindMapNode("apps", "APLICACIONES", "Identificadas en historial",
                observedApps.size.toString(), 0.08f, 0.68f, -0.35f, Color(0xFF58D6B0))
        )
    }
    val selectedNode = when (section) {
        "red" -> "tun"
        "dns" -> "dns"
        "amenazas" -> "threats"
        "reglas" -> "rules"
        "apps" -> "apps"
        else -> "core"
    }
    if (section == "map") {
        LazyColumn(
            Modifier.fillMaxSize().padding(horizontal = 8.dp, vertical = 6.dp),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 14.dp),
            verticalArrangement = Arrangement.spacedBy(9.dp)
        ) {
            item { SocHeader(vpnRunning = vpnRunning, metrics = tunMetrics) }
            item {
                ThreeDimensionalMindMap(nodes = nodes, selectedNode = selectedNode) { id ->
                    section = when (id) {
                        "tun" -> "red"
                        "dns" -> "dns"
                        "threats" -> "amenazas"
                        "rules" -> "reglas"
                        "apps" -> "apps"
                        else -> "map"
                    }
                }
            }
            item { SocKpiGrid(metrics = tunMetrics) }
            item { SocPolicyDiagnostics(metrics = tunMetrics) }
            item { SocTunnelPath(metrics = tunMetrics, vpnRunning = vpnRunning) }
            item { LiveMapTelemetry(metrics = tunMetrics, logs = logs, vpnRunning = vpnRunning) }
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
        Column(Modifier.fillMaxSize()) {
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
                        "Consultas UDP" to tunMetrics.dnsUdpPackets,
                        "Consultas TCP" to tunMetrics.dnsTcp
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
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
                    FlowStage("ENTRADA", "TUN", metrics.packetsRead.toString(), Modifier.weight(1f))
                    Text("›", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                    FlowStage("INSPECCIÓN", "DNS", (metrics.dnsUdpPackets + metrics.dnsTcp).toString(), Modifier.weight(1f))
                    Text("›", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                    FlowStage("DECISIÓN", "B/O/P", "${metrics.dnsBlocked}/${metrics.dnsObserved}/${metrics.dnsAllowed}", Modifier.weight(1f))
                    Text("›", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                    FlowStage("SALIDA", "Flujos", metrics.flowsActive.toString(), Modifier.weight(1f))
                }
                Text("Contadores acumulados del servicio · B bloqueado · O observado · P permitido", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
    onSelectNode: (String) -> Unit
) {
    val transition = rememberInfiniteTransition(label = "mind-map-3d")
    val rotation by transition.animateFloat(
        initialValue = 0f,
        targetValue = (Math.PI * 2.0).toFloat(),
        animationSpec = infiniteRepeatable(tween(18000, easing = LinearEasing), RepeatMode.Restart),
        label = "mind-map-rotation"
    )
    val latestRotation by rememberUpdatedState(rotation)
    val pulse by transition.animateFloat(
        initialValue = 0.72f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1500), RepeatMode.Reverse),
        label = "mind-map-pulse"
    )
    val flowPhase by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(2600, easing = LinearEasing), RepeatMode.Restart),
        label = "mind-map-flow-particles"
    )
    val background = MaterialTheme.colorScheme.surface
    val lineColor = MaterialTheme.colorScheme.outlineVariant
    val onSurface = MaterialTheme.colorScheme.onSurface
    val density = LocalDensity.current.density
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = background)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("TOPOLOGÍA SOC · FIREWALLDNS", Modifier.weight(1f),
                    style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                Text("3D · EN MOVIMIENTO", style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary)
            }
            Canvas(
                Modifier.fillMaxWidth().height(320.dp)
                    .pointerInput(Unit) {
                        detectTapGestures { tap ->
                            val hit = nodes.map { node ->
                                val point = projectNode(node, size.width.toFloat(), size.height.toFloat(), latestRotation)
                                val dx = point.x - tap.x
                                val dy = point.y - tap.y
                                node to (dx * dx + dy * dy)
                            }.filter { it.second < 46f * 46f }
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

                    // Layered orbital rings create depth without representing real network geography.
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

                    // Edges are the real code-path topology: TUN -> DNS -> policy,
                    // with catalog, rules and app identity feeding policy decisions.
                    val byId = nodes.associateBy { it.id }
                    architectureEdges.forEach { edge ->
                        val from = byId[edge.from] ?: return@forEach
                        val to = byId[edge.to] ?: return@forEach
                        val start = projected.getValue(from)
                        val end = projected.getValue(to)
                        basePaint.style = Paint.Style.STROKE
                        basePaint.strokeWidth = 2.1f
                        basePaint.color = to.tint.copy(alpha = .58f).toArgb()
                        canvas.drawLine(start.x, start.y, end.x, end.y, basePaint)

                        // Animated route markers visualize the architecture only.
                        // They are deliberately not presented as captured network packets.
                        val particle = (flowPhase + edge.from.hashCode().mod(17) / 17f) % 1f
                        val px = start.x + (end.x - start.x) * particle
                        val py = start.y + (end.y - start.y) * particle
                        basePaint.style = Paint.Style.FILL
                        basePaint.color = to.tint.copy(alpha = .95f).toArgb()
                        basePaint.setShadowLayer(10f, 0f, 0f, to.tint.toArgb())
                        canvas.drawCircle(px, py, 3.2f * density, basePaint)
                        basePaint.clearShadowLayer()
                        canvas.drawCircle(px, py, 1.4f * density, android.graphics.Paint().apply {
                            color = android.graphics.Color.WHITE
                            isAntiAlias = true
                        })
                    }

                    // Back-to-front sorting makes nearer nodes larger and visually layered.
                    nodes.sortedBy { projected.getValue(it).y }.forEach { node ->
                        val point = projected.getValue(node)
                        val depth = (point.zDepth + 1f) / 2f
                        val nodeRadius = (if (node.id == "core") 17f else 11f) * (.78f + depth * .38f)
                        val isSelected = node.id == selectedNode
                        basePaint.style = Paint.Style.FILL
                        basePaint.color = node.tint.copy(alpha = .12f * pulse).toArgb()
                        canvas.drawCircle(point.x, point.y, nodeRadius * 2.8f * pulse, basePaint)
                        basePaint.color = node.tint.copy(alpha = .24f).toArgb()
                        canvas.drawCircle(point.x, point.y, nodeRadius * 1.65f, basePaint)
                        basePaint.color = node.tint.toArgb()
                        basePaint.setShadowLayer(12f, 0f, 4f, node.tint.copy(alpha = .75f).toArgb())
                        canvas.drawCircle(point.x, point.y, nodeRadius * if (isSelected) 1.18f else 1f, basePaint)
                        basePaint.clearShadowLayer()
                        basePaint.color = android.graphics.Color.WHITE
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
            Text("Animación 3D de la arquitectura y sus rutas funcionales. Los puntos luminosos son un efecto visual, no paquetes capturados. Las cifras se alimentan de la telemetría real.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
            SocKpi("PAQUETES TUN", metrics.packetsRead.toString(), "IPv4 ${metrics.ipv4Packets} · IPv6 ${metrics.ipv6Packets}", Color(0xFF2776B8), Modifier.weight(1f))
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
                Triple("ENTRADA TUN", metrics.packetsRead, "Paquetes recibidos"),
                Triple("CLASIFICACIÓN IP", metrics.ipv4Packets + metrics.ipv6Packets, "IPv4 + IPv6"),
                Triple("POLÍTICA DNS", metrics.dnsBlocked + metrics.dnsObserved + metrics.dnsAllowed, "Bloquear · observar · permitir"),
                Triple("FLUJOS", metrics.flowsOpened, "Conexiones abiertas"),
                Triple("SALIDA TUN", metrics.packetsWritten, "Paquetes escritos")
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
                MapStatPill("TUN", metrics.packetsRead.toString(), Color(0xFF1C806B))
                MapStatPill("DNS", (metrics.dnsUdpPackets + metrics.dnsTcp).toString(), Color(0xFF315FA8))
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
                if (vpnRunning) "Lectura de contadores del servicio activo. Los valores son acumulados reales desde que se inició el proceso."
                else "Servicio detenido. Se muestran los últimos contadores disponibles; no se simula actividad.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        LiveMetricSection("TRÁFICO TUN · PAQUETES", listOf(
            "Paquetes leídos" to metrics.packetsRead,
            "Paquetes escritos" to metrics.packetsWritten,
            "IPv4 recibidos" to metrics.ipv4Packets,
            "IPv6 recibidos" to metrics.ipv6Packets,
            "Errores de escritura" to metrics.writeErrors,
            "Rechazos de cola" to metrics.queueRejected,
            "Rechazos de parser" to metrics.parserRejected,
            "Transporte no compatible" to metrics.unsupportedTransport,
        ))
        LiveMetricSection("INSPECCIÓN DNS Y DECISIONES", listOf(
            "Consultas DNS UDP" to metrics.dnsUdpPackets,
            "Consultas DNS TCP" to metrics.dnsTcp,
            "DNS malformado" to metrics.malformedDns,
            "Bloqueadas" to metrics.dnsBlocked,
            "Observadas" to metrics.dnsObserved,
            "Permitidas" to metrics.dnsAllowed,
            "Rechazadas" to metrics.dnsRejected,
            "Aciertos de caché" to metrics.cacheHits,
            "Fallos de caché" to metrics.cacheMisses,
        ))
        LiveMetricSection("RESOLUCIÓN Y RED FÍSICA", listOf(
            "Respuestas upstream correctas" to metrics.upstreamSuccess,
            "Fallos upstream" to metrics.upstreamFailure,
            "Intentos fallidos upstream" to metrics.upstreamAttemptFailures,
            "Timeouts upstream" to metrics.upstreamFailureTimeouts,
            "Cancelaciones upstream" to metrics.upstreamCancelled,
            "Cambios de resolvers" to metrics.upstreamResolverRefreshes,
            "Intentos proteger UDP" to metrics.upstreamProtectUdpAttempts,
            "Intentos proteger TCP" to metrics.upstreamProtectTcpAttempts,
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
        ))
        LiveActiveFlows(metrics.activeFlows)
        LiveMetricSection("FRAGMENTACIÓN Y PROTECCIÓN DE SOCKETS", listOf(
            "Fragmentos aceptados" to metrics.fragmentsAccepted,
            "Paquetes reensamblados" to metrics.packetsReassembled,
            "Fragmentos inválidos" to metrics.fragmentsDroppedInvalid,
            "Fragmentos exceden límites" to metrics.fragmentsDroppedLimit,
            "Ensamblajes pendientes" to metrics.fragmentPendingAssemblies,
            "Bytes fragmentados en buffer" to metrics.fragmentBufferedBytes,
            "Protección socket correcta" to metrics.firestackProtectSuccess,
            "Fallos protección socket" to metrics.firestackProtectFailure,
            "Vinculación a red correcta" to metrics.firestackBindSuccess,
            "Fallos vinculación a red" to metrics.firestackBindFailure,
        ))
        LiveMetricSection("ESTADO DE ERRORES", listOf(
            "Errores de workers" to metrics.workerErrors,
            "Respuestas DNS construidas" to metrics.dnsResponsesBuilt,
            "Respuestas DNS ausentes" to metrics.noDnsResponse,
            "RST TCP enviados" to metrics.tcpRstSent,
            "RST TCP suprimidos" to metrics.tcpRstSuppressed,
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
                            "${flow.identity.appPackage ?: "Aplicación no identificada"} · TX ${flow.bytesSent} B · RX ${flow.bytesReceived} B",
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
