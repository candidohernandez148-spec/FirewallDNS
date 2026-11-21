package com.firewall.dns.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.firewall.dns.domain.engine.ThreatKnowledgeGraph
import com.firewall.dns.domain.model.DnsLogEntry

/**
 * Mobile knowledge map. Curated intelligence and observed device events are
 * deliberately shown as separate sources. Actions create real repository rules.
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
            start = 14.dp, top = 12.dp, end = 14.dp, bottom = 24.dp
        ),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                Text("Mapa de conocimiento", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Text(
                    "Relaciones de proveedores, dominios observados y reglas que controlan el filtrado.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Fuentes de información", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Surface(shape = RoundedCornerShape(10.dp), color = MaterialTheme.colorScheme.secondaryContainer) {
                            Text("Catálogo local: ${catalog.size}", Modifier.padding(horizontal = 9.dp, vertical = 6.dp), style = MaterialTheme.typography.labelMedium)
                        }
                        Surface(shape = RoundedCornerShape(10.dp), color = MaterialTheme.colorScheme.primaryContainer) {
                            Text("Dominios observados: ${observedDomains.size}", Modifier.padding(horizontal = 9.dp, vertical = 6.dp), style = MaterialTheme.typography.labelMedium)
                        }
                    }
                    Text(
                        "El catálogo contiene relaciones curadas. Los dominios observados proceden del historial real conservado en este dispositivo. No se afirma aprendizaje persistente automático.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        item {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                leadingIcon = { androidx.compose.material3.Icon(Icons.Default.Search, contentDescription = null) },
                label = { Text("Buscar proveedor o dominio") },
                shape = RoundedCornerShape(14.dp)
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
                val domains = listOf(evidence.provider)
                val blocked = domains.any { domain -> customBlock.any { it.equals(domain, true) } }
                val allowed = domains.any { domain -> customAllow.any { it.equals(domain, true) } }
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                ) {
                    Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(evidence.provider, modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                            Text(
                                when {
                                    blocked -> "REGLA: BLOQUEAR"
                                    allowed -> "REGLA: PERMITIR"
                                    else -> "CATÁLOGO"
                                },
                                style = MaterialTheme.typography.labelSmall,
                                color = if (blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                            )
                        }
                        Text(
                            "${categoryLabel(evidence.category)} · Confianza ${if (evidence.confidence == ThreatKnowledgeGraph.Confidence.HIGH) "alta" else "media"}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            NodePill(evidence.platform ?: "Internet")
                            Text("→", color = MaterialTheme.colorScheme.primary)
                            NodePill(evidence.provider)
                            Text("→", color = MaterialTheme.colorScheme.primary)
                            NodePill(evidence.relation)
                        }
                        Text(
                            evidence.knowledgePath.joinToString("  ›  "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { onSetRule(evidence.provider, true) },
                                modifier = Modifier.weight(1f),
                                enabled = !blocked
                            ) { Text("Bloquear") }
                            Button(
                                onClick = { onSetRule(evidence.provider, false) },
                                modifier = Modifier.weight(1f),
                                enabled = !allowed
                            ) { Text("Permitir") }
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
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                ) {
                    Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(domain, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                        Text(
                            when {
                                blocked -> "Regla personalizada: bloqueado"
                                allowed -> "Regla personalizada: permitido"
                                event?.isBlocked == true -> "Último evento: bloqueado"
                                else -> "Último evento: no bloqueado"
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        if (evidence != null) {
                            Text("${categoryLabel(evidence.category)} · proveedor ${evidence.provider}", style = MaterialTheme.typography.bodySmall)
                        }
                        Text(event?.reason ?: "Sin motivo disponible en el historial", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = { onSetRule(domain, true) }, modifier = Modifier.weight(1f)) { Text("Bloquear") }
                            Button(onClick = { onSetRule(domain, false) }, modifier = Modifier.weight(1f)) { Text("Permitir") }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun NodePill(label: String) {
    Surface(shape = RoundedCornerShape(8.dp), color = MaterialTheme.colorScheme.surfaceVariant) {
        Text(label, modifier = Modifier.padding(horizontal = 7.dp, vertical = 5.dp), style = MaterialTheme.typography.labelSmall)
    }
}

private fun categoryLabel(category: ThreatKnowledgeGraph.Category): String = when (category) {
    ThreatKnowledgeGraph.Category.ADVERTISING -> "Publicidad"
    ThreatKnowledgeGraph.Category.TRACKING -> "Rastreo"
    ThreatKnowledgeGraph.Category.ANALYTICS -> "Analítica"
}
