package com.firewall.dns.ui.screens

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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.firewall.dns.domain.engine.ThreatKnowledgeGraph
import com.firewall.dns.domain.model.DnsLogEntry

/**
 * Knowledge map: the animated network is a visual guide, while all counts,
 * domains and rule states below come from the actual local catalog and history.
 */
@Composable
fun ThreatMapScreen(
    logs: List<DnsLogEntry>,
    customBlock: List<String>,
    customAllow: List<String>,
    onSetRule: (String, Boolean) -> Unit,
) {
    var query by remember { mutableStateOf("") }
    var showObserved by remember { mutableStateOf(false) }
    val catalog = remember { ThreatKnowledgeGraph.catalogSnapshot() }
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

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(
            start = 14.dp, top = 12.dp, end = 14.dp, bottom = 26.dp
        ),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Mapa de amenazas", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Text("Vista de relaciones, actividad observada y reglas del firewall.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        item {
            AnimatedNetworkMap(
                catalogCount = catalog.size,
                observedCount = observedDomains.size,
                blockedCount = customBlock.size,
                allowedCount = customAllow.size
            )
        }
        item {
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(17.dp)) {
                Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Fuentes de información", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                        Surface(shape = RoundedCornerShape(9.dp), color = MaterialTheme.colorScheme.secondaryContainer) {
                            Text("Catálogo: ${catalog.size}", Modifier.padding(horizontal = 9.dp, vertical = 6.dp),
                                style = MaterialTheme.typography.labelMedium)
                        }
                        Surface(shape = RoundedCornerShape(9.dp), color = MaterialTheme.colorScheme.primaryContainer) {
                            Text("Observados: ${observedDomains.size}", Modifier.padding(horizontal = 9.dp, vertical = 6.dp),
                                style = MaterialTheme.typography.labelMedium)
                        }
                    }
                    Text("El mapa animado es una guía visual. Los datos de dominios y reglas se obtienen del catálogo local y del historial del dispositivo; no representa conexiones geográficas ni inventa tráfico.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
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
                Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(15.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
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
                Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
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
private fun AnimatedNetworkMap(catalogCount: Int, observedCount: Int, blockedCount: Int, allowedCount: Int) {
    val pulse = rememberInfiniteTransition(label = "network-map-pulse")
        .animateFloat(0.35f, 1f, infiniteRepeatable(tween(1250), RepeatMode.Reverse),
            label = "network-node-pulse").value
    val primary = MaterialTheme.colorScheme.primary
    val secondary = MaterialTheme.colorScheme.secondary
    val error = MaterialTheme.colorScheme.error
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Red de relaciones", Modifier.weight(1f), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Text("ANIMACIÓN", style = MaterialTheme.typography.labelSmall, color = primary)
            }
            Canvas(Modifier.fillMaxWidth().height(158.dp)) {
                val w = size.width
                val h = size.height
                val center = Offset(w * .5f, h * .50f)
                val nodes = listOf(
                    Offset(w * .16f, h * .22f), Offset(w * .82f, h * .18f),
                    Offset(w * .17f, h * .78f), Offset(w * .83f, h * .77f),
                    Offset(w * .50f, h * .12f), Offset(w * .50f, h * .88f)
                )
                nodes.forEachIndexed { index, point ->
                    drawLine(primary.copy(alpha = .42f), center, point, strokeWidth = 2.dp.toPx(), cap = StrokeCap.Round)
                    drawCircle(primary.copy(alpha = .12f + .18f * pulse), radius = 11.dp.toPx() * pulse, center = point)
                    drawCircle(if (index % 2 == 0) secondary else error, radius = 5.dp.toPx(), center = point)
                }
                drawCircle(primary.copy(alpha = .12f + .18f * pulse), radius = 25.dp.toPx() * pulse, center = center)
                drawCircle(primary, radius = 13.dp.toPx(), center = center)
                drawCircle(MaterialTheme.colorScheme.surface, radius = 5.dp.toPx(), center = center)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MapLegendDot(primary, "Catálogo")
                MapLegendDot(secondary, "Permitidas")
                MapLegendDot(error, "Bloqueadas")
            }
            Text("Catálogo $catalogCount · historial $observedCount · reglas de bloqueo $blockedCount · reglas de permiso $allowedCount",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun MapLegendDot(color: androidx.compose.ui.graphics.Color, label: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(5.dp)) {
        Surface(shape = RoundedCornerShape(50), color = color, modifier = Modifier.height(8.dp).fillMaxWidth(.035f)) {}
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
