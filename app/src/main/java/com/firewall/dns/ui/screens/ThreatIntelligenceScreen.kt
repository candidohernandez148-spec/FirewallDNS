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
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.firewall.dns.domain.engine.ThreatKnowledgeGraph

@Composable
fun ThreatIntelligenceScreen() {
    val catalog = remember { ThreatKnowledgeGraph.catalogSnapshot() }
    val learnedCount = remember { ThreatKnowledgeGraph.learnedProfileCount() }
    var query by remember { mutableStateOf("") }
    var expandedProvider by remember { mutableStateOf<String?>(null) }

    val filtered = catalog.filter { evidence ->
        val text = listOfNotNull(evidence.platform, evidence.provider, evidence.category.name)
            .joinToString(" ").lowercase()
        text.contains(query.trim().lowercase())
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Mapa de inteligencia", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Text(
                    "Relaciones conocidas entre plataformas, proveedores y dominios. El catálogo se consulta localmente.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
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
            Surface(color = MaterialTheme.colorScheme.secondaryContainer, shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth()) {
                Text(
                    "El aprendizaje muestra perfiles agregados con al menos 8 observaciones. No identifica qué aplicación originó cada consulta.",
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSecondaryContainer
                )
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
            Text("Relaciones del catálogo (\${filtered.size})", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
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
                        if (expanded) "Ocultar evidencia" else "Ver relaciones y evidencia  ·  \${evidence.relation}",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    if (expanded) {
                        Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = RoundedCornerShape(10.dp), modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                evidence.knowledgePath.forEachIndexed { index, step ->
                                    Text((index + 1).toString() + ". " + step, style = MaterialTheme.typography.bodySmall)
                                }
                                Text("Fuente: \${evidence.source}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Text(
                                    "Decisión: " + if (evidence.category == ThreatKnowledgeGraph.Category.ADVERTISING && evidence.confidence == ThreatKnowledgeGraph.Confidence.HIGH) "puede bloquearse" else "se observa; no se bloquea automáticamente",
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
