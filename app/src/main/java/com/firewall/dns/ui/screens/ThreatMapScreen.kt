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
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
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
    var query by remember { mutableStateOf("") }
    var showObserved by remember { mutableStateOf(false) }
    var selectedNode by remember { mutableStateOf("core") }
    val catalog = remember { ThreatKnowledgeGraph.catalogSnapshot() }
    val knownObserved = logs.map { it.domain.trim().lowercase().trimEnd('.') }
        .distinct().count { ThreatKnowledgeGraph.inspect(it) != null }
    val observedApps = logs.map { it.appName }.filter { it.isNotBlank() }.distinct().size
    val mindMapNodes = remember(logs, customBlock, customAllow, tunMetrics, vpnRunning,
        smartModeEnabled, observationModeEnabled, catalog) {
        listOf(
            MindMapNode("core", "FIREWALL DNS", "Servicio VPN: estado real", if (vpnRunning) "ACTIVO" else "DETENIDO",
                0f, 0f, 0f, Color(0xFF42D9FF)),
            MindMapNode("tun", "TÚNEL TUN", "Paquetes leídos por el servicio", tunMetrics.packetsRead.toString(),
                -0.88f, -0.55f, -0.18f, Color(0xFF58D6B0)),
            MindMapNode("dns", "CONSULTAS DNS", "UDP + TCP observados por el servicio",
                (tunMetrics.dnsUdpPackets + tunMetrics.dnsTcp).toString(),
                0.82f, -0.63f, 0.20f, Color(0xFF78A8FF)),
            MindMapNode("decisions", "DECISIONES", "Bloqueadas / observadas / permitidas",
                "${tunMetrics.dnsBlocked} / ${tunMetrics.dnsObserved} / ${tunMetrics.dnsAllowed}",
                -0.96f, 0.48f, 0.24f, Color(0xFFFF667D)),
            MindMapNode("threats", "CATÁLOGO", "Proveedores curados / dominios coincidentes",
                "${catalog.size} / $knownObserved",
                0.96f, 0.46f, -0.22f, Color(0xFFFFB454)),
            MindMapNode("rules", "REGLAS", "Reglas personalizadas de usuario",
                "${customBlock.size} bloqueo · ${customAllow.size} permiso",
                -0.18f, 0.94f, -0.42f, Color(0xFFB69CFF)),
            MindMapNode("upstream", "DNS ASCENDENTE", "Respuestas / fallos upstream",
                "${tunMetrics.upstreamSuccess} / ${tunMetrics.upstreamFailure}",
                0.20f, -0.98f, 0.42f, Color(0xFF68D9A5)),
            MindMapNode("apps", "APLICACIONES", "Apps identificadas en el historial",
                observedApps.toString(),
                0.08f, 0.68f, -0.35f, Color(0xFF58D6B0))
        )
    }
    val observedDomains = logs.asSequence()
        .map { it.domain.trim().lowercase().trimEnd('.') }
        .filter { it.isNotBlank() }
        .distinct()
        .filter { query.isBlank() || it.contains(query, ignoreCase = true) }
        .take(40)
        .toList()
    val filteredCatalog = catalog.filter { evidence ->
        query.isBlank() || evidence.provider.contains(query, true) ||
            evidence.platform.orEmpty().contains(query, true)
    }
    val selected = mindMapNodes.firstOrNull { it.id == selectedNode } ?: mindMapNodes.first()
    val selectedDescription = when (selected.id) {
        "tun" -> "Contador del servicio TUN: ${tunMetrics.packetsRead} paquetes leídos. Es acumulado del proceso actual."
        "dns" -> "Consultas contabilizadas: UDP ${tunMetrics.dnsUdpPackets}, TCP ${tunMetrics.dnsTcp}. No representa DoH/DoT."
        "decisions" -> "Contadores del servicio: ${tunMetrics.dnsBlocked} bloqueadas, ${tunMetrics.dnsObserved} observadas y ${tunMetrics.dnsAllowed} permitidas."
        "threats" -> "Catálogo local curado: ${catalog.size} proveedores. Coincidencias en el historial visible: $knownObserved dominios."
        "apps" -> "Aplicaciones distintas identificadas en el historial visible: $observedApps. No es un contador total de apps instaladas."
        "rules" -> "Reglas personalizadas: ${customBlock.size} bloqueos y ${customAllow.size} permisos. Listas descargadas no se incluyen en esta cifra."
        "upstream" -> "Respuestas upstream exitosas: ${tunMetrics.upstreamSuccess}; fallidas: ${tunMetrics.upstreamFailure}."
        else -> "VPN: ${if (vpnRunning) "activa" else "detenida"}. Modo inteligente: ${if (smartModeEnabled) "activo" else "inactivo"}. Observación: ${if (observationModeEnabled) "activa" else "inactiva"}."
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(
            start = 14.dp, top = 12.dp, end = 14.dp, bottom = 26.dp
        ),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Mapa mental de seguridad", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Text("Arquitectura del servicio y telemetría real; no representa conexiones geográficas.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        item {
            ThreeDimensionalMindMap(
                nodes = mindMapNodes,
                selectedNode = selectedNode,
                onSelectNode = { selectedNode = it }
            )
        }
        item {
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
                Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Text(selected.label, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold,
                        color = selected.tint)
                    Text(selectedDescription, style = MaterialTheme.typography.bodySmall)
                    Text("Las ramas muestran componentes del proceso. Los valores vienen de contadores del servicio, reglas e historial; no se generan eventos ficticios.",
                        style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                MapStatPill("VPN", if (vpnRunning) "ACTIVA" else "DETENIDA", MaterialTheme.colorScheme.secondaryContainer)
                MapStatPill("TUN", tunMetrics.packetsRead.toString(), MaterialTheme.colorScheme.primaryContainer)
                MapStatPill("Coincidencias", knownObserved.toString(), MaterialTheme.colorScheme.errorContainer)
            }
        }
        item {
            OutlinedTextField(
                value = query, onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(), singleLine = true,
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                label = { Text("Buscar proveedor o dominio") },
                shape = RoundedCornerShape(13.dp)
            )
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = !showObserved, onClick = { showObserved = false }, label = { Text("Catálogo") })
                FilterChip(selected = showObserved, onClick = { showObserved = true }, label = { Text("Actividad real") })
            }
        }
        if (!showObserved) {
            if (filteredCatalog.isEmpty()) {
                item { Text("No hay coincidencias en el catálogo.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
            items(filteredCatalog, key = { "${it.provider}-${it.category}" }) { evidence ->
                val blocked = customBlock.any { it.equals(evidence.provider, true) }
                val allowed = customAllow.any { it.equals(evidence.provider, true) }
                Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(15.dp)) {
                    Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(evidence.provider, Modifier.weight(1f), style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold)
                            Text(when {
                                blocked -> "BLOQUEAR"
                                allowed -> "PERMITIR"
                                else -> "CATÁLOGO"
                            }, style = MaterialTheme.typography.labelSmall,
                                color = if (blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
                        }
                        Text("${categoryLabel(evidence.category)} · Confianza ${if (evidence.confidence == ThreatKnowledgeGraph.Confidence.HIGH) "alta" else "media"}",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            NodePill(evidence.platform ?: "Internet")
                            Text("→", color = MaterialTheme.colorScheme.primary)
                            NodePill(evidence.provider)
                            Text("→", color = MaterialTheme.colorScheme.primary)
                            NodePill(evidence.relation)
                        }
                        Text(evidence.knowledgePath.joinToString("  ›  "), style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = { onSetRule(evidence.provider, true) }, Modifier.weight(1f), enabled = !blocked) { Text("Bloquear") }
                            Button(onClick = { onSetRule(evidence.provider, false) }, Modifier.weight(1f), enabled = !allowed) { Text("Permitir") }
                        }
                    }
                }
            }
        } else {
            if (observedDomains.isEmpty()) {
                item { Text("Todavía no hay dominios en el historial que coincidan con la búsqueda.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
            items(observedDomains, key = { it }) { domain ->
                val event = logs.lastOrNull { it.domain.equals(domain, true) }
                val blocked = customBlock.any { domain == it || domain.endsWith(".$it") }
                val allowed = customAllow.any { domain == it || domain.endsWith(".$it") }
                val evidence = ThreatKnowledgeGraph.inspect(domain)
                Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp)) {
                    Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                        Text(domain, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                        Text(when {
                            blocked -> "Regla personalizada: bloqueado"
                            allowed -> "Regla personalizada: permitido"
                            event?.isBlocked == true -> "Último evento: bloqueado"
                            else -> "Último evento: no bloqueado"
                        }, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        if (evidence != null) {
                            Text("${categoryLabel(evidence.category)} · proveedor ${evidence.provider}", style = MaterialTheme.typography.bodySmall)
                        }
                        Text(event?.reason ?: "Sin motivo disponible en el historial",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = { onSetRule(domain, true) }, Modifier.weight(1f)) { Text("Bloquear") }
                            Button(onClick = { onSetRule(domain, false) }, Modifier.weight(1f)) { Text("Permitir") }
                        }
                    }
                }
            }
        }
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
    val background = MaterialTheme.colorScheme.surface
    val lineColor = MaterialTheme.colorScheme.outlineVariant
    val onSurface = MaterialTheme.colorScheme.onSurface
    val density = LocalDensity.current.density
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = background)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("TOPOLOGÍA DEL MOTOR", Modifier.weight(1f),
                    style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                Text("3D · EN MOVIMIENTO", style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary)
            }
            Canvas(
                Modifier.fillMaxWidth().height(252.dp)
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

                    // Draw branches first, then moving signal particles along each branch.
                    val center = projected.getValue(nodes.first())
                    nodes.drop(1).forEachIndexed { _, node ->
                        val point = projected.getValue(node)
                        basePaint.style = Paint.Style.STROKE
                        basePaint.strokeWidth = 2.1f
                        basePaint.color = node.tint.copy(alpha = .56f).toArgb()
                        canvas.drawLine(center.x, center.y, point.x, point.y, basePaint)
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
            Text("La animación solo aporta perspectiva. Las líneas representan la arquitectura del proceso; no son paquetes ni conexiones activas.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
