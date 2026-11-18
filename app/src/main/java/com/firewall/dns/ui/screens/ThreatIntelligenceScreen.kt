package com.firewall.dns.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.firewall.dns.domain.engine.ThreatKnowledgeGraph

@Composable
fun ThreatIntelligenceScreen() {
    var refreshKey by remember { mutableIntStateOf(0) }
    val catalog = remember(refreshKey) { ThreatKnowledgeGraph.catalogSnapshot() }
    val learnedCount = remember(refreshKey) { ThreatKnowledgeGraph.learnedProfileCount() }
    val correlations = remember(refreshKey) { ThreatKnowledgeGraph.correlationSnapshot() }
    val adaptivePatterns = remember(refreshKey) { ThreatKnowledgeGraph.adaptivePatternSnapshot() }
    val unattributedCount = remember(refreshKey) { ThreatKnowledgeGraph.unattributedLearnedProfileCount() }
    var query by remember { mutableStateOf("") }
    var expandedProvider by remember { mutableStateOf<String?>(null) }

    val filtered = catalog.filter { evidence ->
        val text = listOfNotNull(evidence.platform, evidence.provider, evidence.category.name)
            .joinToString(" ").lowercase()
        text.contains(query.trim().lowercase())
    }
    val totalListed = correlations.sumOf { it.listedDomainCount }
    val totalCorrelatedObservations = correlations.sumOf { it.totalObservations }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Mapa de inteligencia", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Text(
                    "Conocimiento local que relaciona proveedores conocidos con actividad observada y reglas activas.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Button(onClick = { refreshKey++ }) { Text("Actualizar mapa") }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SummaryTile("Proveedores", catalog.size.toString(), Modifier.weight(1f))
                SummaryTile("Plataformas", catalog.mapNotNull { it.platform }.distinct().size.toString(), Modifier.weight(1f))
                SummaryTile("Perfiles aprendidos", learnedCount.toString(), Modifier.weight(1f))
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SummaryTile("Dominios en listas", totalListed.toString(), Modifier.weight(1f))
                SummaryTile("Observaciones correlacionadas", totalCorrelatedObservations.toString(), Modifier.weight(1f))
                SummaryTile("Sin atribución", unattributedCount.toString(), Modifier.weight(1f))
            }
        }
        item {
            Surface(color = MaterialTheme.colorScheme.secondaryContainer, shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth()) {
                Text(
                    "Las correlaciones solo se muestran cuando existe una relación explícita en el catálogo. Los perfiles desconocidos permanecen sin atribución. Esta información no crea bloqueos por sí sola.",
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSecondaryContainer
                )
            }
        }
        item {
            Text("Correlaciones activas", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        }
        if (correlations.isEmpty()) {
            item {
                Text(
                    "Todavía no hay dominios de listas o perfiles aprendidos que coincidan con proveedores conocidos.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        items(correlations, key = { "correlation-${it.provider}" }) { correlation ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Text(correlation.platform ?: "Proveedor independiente", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                    Text(correlation.provider, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(categoryLabel(correlation.category), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(
                        "Listas activas: ${correlation.listedDomainCount} · Dominios aprendidos: ${correlation.observedDomains.size}",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Text(
                        "Permisos: ${correlation.allowedCount} · Bloqueos: ${correlation.blockedCount}",
                        style = MaterialTheme.typography.bodySmall
                    )
                    if (correlation.observedDomains.isNotEmpty()) {
                        Text(
                            "Dominios: ${correlation.observedDomains.take(5).joinToString(", ")}" +
                                if (correlation.observedDomains.size > 5) " y ${correlation.observedDomains.size - 5} más" else "",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Text(
                        "Relación basada en catálogo explícito; no cambia la decisión DNS.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.tertiary
                    )
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SummaryTile("Patrones recurrentes", adaptivePatterns.size.toString(), Modifier.weight(1f))
                SummaryTile("Dominios en patrones", adaptivePatterns.sumOf { it.domains.size }.toString(), Modifier.weight(1f))
            }
        }
        item {
            Text("Detecciones adaptativas", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(
                "Patrones repetidos entre dominios desconocidos. Son indicios para investigar, no amenazas confirmadas.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        if (adaptivePatterns.isEmpty()) {
            item {
                Text(
                    "Aún no hay patrones repetidos con suficiente historial. El motor seguirá observando sin atribuir ni bloquear por esta señal.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        items(adaptivePatterns, key = { "adaptive-${it.indicators.joinToString("-")}" }) { pattern ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("OBSERVAR", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.tertiary, fontWeight = FontWeight.Bold)
                        Text(
                            if (pattern.confidence == ThreatKnowledgeGraph.PatternConfidence.MEDIUM) "Confianza media" else "Confianza inicial",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Text(pattern.indicators.joinToString(" + "), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text("${pattern.domains.size} dominios · ${pattern.totalObservations} observaciones", style = MaterialTheme.typography.bodySmall)
                    Text("Permisos: ${pattern.allowedCount} · Bloqueos: ${pattern.blockedCount}", style = MaterialTheme.typography.bodySmall)
                    Text(
                        "Dominios: ${pattern.domains.take(5).joinToString(", ")}" +
                            if (pattern.domains.size > 5) " y ${pattern.domains.size - 5} más" else "",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "Sin proveedor atribuido. No modifica la decisión DNS ni activa bloqueos.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.tertiary
                    )
                }
            }
        }
        item {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Buscar plataforma o proveedor") },
                singleLine = true
            )
        }
        item {
            Text("Relaciones del catálogo (${filtered.size})", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        }
        items(filtered, key = { it.provider }) { evidence ->
            val expanded = expandedProvider == evidence.provider
            Card(
                modifier = Modifier.fillMaxWidth().clickable { expandedProvider = if (expanded) null else evidence.provider },
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(evidence.platform ?: "Proveedor independiente", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                            Text(evidence.provider, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                        }
                        Text(
                            if (evidence.confidence == ThreatKnowledgeGraph.Confidence.HIGH) "ALTA" else "MEDIA",
                            style = MaterialTheme.typography.labelSmall,
                            color = if (evidence.confidence == ThreatKnowledgeGraph.Confidence.HIGH) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.tertiary,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Text(categoryLabel(evidence.category), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(
                        if (expanded) "Ocultar evidencia" else "Ver relaciones y evidencia · ${evidence.relation}",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    if (expanded) {
                        Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = RoundedCornerShape(10.dp), modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                evidence.knowledgePath.forEachIndexed { index, step ->
                                    Text("${index + 1}. $step", style = MaterialTheme.typography.bodySmall)
                                }
                                Text("Fuente: ${evidence.source}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Text(
                                    "Decisión: " + if (evidence.category == ThreatKnowledgeGraph.Category.ADVERTISING && evidence.confidence == ThreatKnowledgeGraph.Confidence.HIGH) "puede bloquearse según la política del motor" else "se observa; no se bloquea automáticamente",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }
                    }
                }
            }
        }
        if (filtered.isEmpty()) {
            item { Text("No hay coincidencias en el catálogo conocido.", color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 16.dp)) }
        }
        item { Spacer(Modifier.padding(bottom = 8.dp)) }
    }
}

@Composable
private fun SummaryTile(label: String, value: String, modifier: Modifier = Modifier) {
    Card(modifier = modifier, shape = RoundedCornerShape(14.dp)) {
        Column(modifier = Modifier.fillMaxWidth().padding(10.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

private fun categoryLabel(category: ThreatKnowledgeGraph.Category): String = when (category) {
    ThreatKnowledgeGraph.Category.ADVERTISING -> "Publicidad"
    ThreatKnowledgeGraph.Category.TRACKING -> "Rastreo"
    ThreatKnowledgeGraph.Category.ANALYTICS -> "Analítica"
}
