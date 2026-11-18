package com.firewall.dns.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.firewall.dns.domain.model.FirewallStats
import com.firewall.dns.domain.model.BlocklistDownloadProgress
import com.firewall.dns.domain.engine.ThreatFeedCatalog

@Composable
fun RulesScreen(
    stats: FirewallStats,
    customBlock: List<String>,
    customAllow: List<String>,
    blocklistUrls: List<String>,
    smartModeEnabled: Boolean,
    isDownloading: Boolean,
    downloadProgress: BlocklistDownloadProgress?,
    onToggleSmartMode: (Boolean) -> Unit,
    onResetLearning: () -> Unit,
    onAddBlocklistUrl: (String) -> Unit,
    onRemoveBlocklistUrl: (String) -> Unit,
    onDownloadBlocklist: () -> Unit,
    onAddCustomRule: (String, Boolean) -> Unit,
    onRemoveCustomRule: (String) -> Unit
) {
    var domainInput by remember { mutableStateOf("") }
    var urlInput by remember { mutableStateOf("") }

    val presets = listOf(
        "Ligera" to "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
        "Estándar" to "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
        "Avanzada" to "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"
    )

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp, vertical = 14.dp),
        contentPadding = PaddingValues(bottom = 20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Reglas y listas", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Text("Controla qué dominios se bloquean o permiten.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(18.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                        Text("Protección inteligente", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        Text(
                            "Aprende de tu actividad de red con ayuda de la lista adblock: detecta dominios nuevos de anuncios y rastreo con patrones ya vistos. Todo se queda en el dispositivo.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        if (smartModeEnabled) {
                            Text(
                                "Patrones aprendidos: ${stats.learnedTokens}",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary
                            )
                            if (stats.learnedTokens > 0) {
                                OutlinedButton(onClick = onResetLearning) { Text("Olvidar aprendizaje") }
                            }
                        }
                    }
                    Switch(checked = smartModeEnabled, onCheckedChange = onToggleSmartMode)
                }
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Listas de bloqueo", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                            Text("${stats.loadedRulesCount} reglas cargadas", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    OutlinedTextField(
                        value = urlInput,
                        onValueChange = { urlInput = it },
                        placeholder = { Text("https://ejemplo.com/lista.txt") },
                        label = { Text("URL HTTPS de lista Adblock") },
                        singleLine = true,
                        shape = RoundedCornerShape(15.dp),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Button(
                        onClick = {
                            onAddBlocklistUrl(urlInput)
                            urlInput = ""
                        },
                        enabled = urlInput.isNotBlank(),
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                        shape = RoundedCornerShape(14.dp)
                    ) { Text("Añadir lista") }
                    Text("Listas recomendadas", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        presets.forEach { (name, url) ->
                            OutlinedButton(
                                onClick = { onAddBlocklistUrl(url) },
                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp),
                                modifier = Modifier.weight(1f),
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                Text(name, fontSize = 12.sp, maxLines = 1)
                            }
                        }
                    }
                    Text("Protección contra amenazas", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(
                        "Feeds especializados. Al actualizar, FirewallDNS identificará la categoría de los dominios bloqueados.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    ThreatFeedCatalog.presets.forEach { preset ->
                        OutlinedButton(
                            onClick = { onAddBlocklistUrl(preset.url) },
                            modifier = Modifier.fillMaxWidth(),
                            contentPadding = PaddingValues(horizontal = 14.dp, vertical = 10.dp),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalAlignment = Alignment.Start,
                                verticalArrangement = Arrangement.spacedBy(2.dp)
                            ) {
                                Text(preset.name, fontWeight = FontWeight.SemiBold)
                                Text(
                                    preset.description,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                    Button(
                        onClick = onDownloadBlocklist,
                        enabled = !isDownloading && blocklistUrls.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth().height(50.dp),
                        shape = RoundedCornerShape(14.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.Center,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            if (isDownloading) {
                                CircularProgressIndicator(
                                    modifier = Modifier.padding(end = 10.dp).size(18.dp),
                                    strokeWidth = 2.dp
                                )
                            }
                            Text(
                                if (isDownloading && downloadProgress?.percent != null)
                                    "Actualizando · ${downloadProgress.percent}%"
                                else if (isDownloading) "Actualizando listas…"
                                else "Descargar y actualizar"
                            )
                        }
                    }
                    if (isDownloading) {
                        val progress = downloadProgress
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.secondaryContainer
                            )
                        ) {
                            Column(
                                modifier = Modifier.fillMaxWidth().padding(16.dp),
                                horizontalAlignment = Alignment.CenterHorizontally,
                                verticalArrangement = Arrangement.spacedBy(9.dp)
                            ) {
                                Text(
                                    when (progress?.phase) {
                                        "Validando" -> "Validando lista"
                                        "Aplicando" -> "Aplicando reglas"
                                        "Completado" -> "Actualización completada"
                                        "Preparando" -> "Preparando descarga"
                                        else -> "Descargando listas"
                                    },
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Text(
                                    if (progress != null && progress.totalSources > 0)
                                        "Fuente ${progress.currentSource.coerceAtLeast(1)} de ${progress.totalSources}"
                                    else "Conectando con las fuentes",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                val percent = progress?.percent
                                if (percent != null) {
                                    LinearProgressIndicator(
                                        progress = { percent / 100f },
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    Text(
                                        "$percent%",
                                        style = MaterialTheme.typography.labelLarge,
                                        fontWeight = FontWeight.Bold
                                    )
                                } else {
                                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                    Text(
                                        "El servidor no informó el tamaño total; mostrando progreso de actividad.",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        if (blocklistUrls.isNotEmpty()) {
            item {
                Text("Listas configuradas · ${blocklistUrls.size}", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            }
            items(blocklistUrls, key = { "url:$it" }) { url ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                ) {
                    Row(modifier = Modifier.padding(start = 14.dp, end = 4.dp, top = 7.dp, bottom = 7.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(url, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
                        IconButton(onClick = { onRemoveBlocklistUrl(url) }) {
                            Icon(Icons.Default.Delete, contentDescription = "Quitar lista")
                        }
                    }
                }
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Regla personalizada", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    Text("Añade una excepción o bloquea un dominio concreto.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    OutlinedTextField(
                        value = domainInput,
                        onValueChange = { domainInput = it },
                        placeholder = { Text("ejemplo.com") },
                        label = { Text("Dominio") },
                        singleLine = true,
                        shape = RoundedCornerShape(15.dp),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(
                            onClick = { onAddCustomRule(domainInput, true); domainInput = "" },
                            enabled = domainInput.isNotBlank(),
                            modifier = Modifier.weight(1f).height(48.dp),
                            shape = RoundedCornerShape(12.dp)
                        ) { Text("Bloquear") }
                        Button(
                            onClick = { onAddCustomRule(domainInput, false); domainInput = "" },
                            enabled = domainInput.isNotBlank(),
                            modifier = Modifier.weight(1f).height(48.dp),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondaryContainer, contentColor = MaterialTheme.colorScheme.onSecondaryContainer)
                        ) { Text("Permitir") }
                    }
                    if (customBlock.isNotEmpty() || customAllow.isNotEmpty()) {
                        Text("Reglas personalizadas activas", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                        if (customBlock.isNotEmpty()) {
                            Text("Bloqueados", style = MaterialTheme.typography.labelMedium)
                            customBlock.forEach { domain ->
                                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                                    Text(domain, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    IconButton(onClick = { onRemoveCustomRule(domain) }) { Icon(Icons.Default.Delete, contentDescription = "Eliminar") }
                                }
                            }
                        }
                        if (customAllow.isNotEmpty()) {
                            Text("Permitidos", style = MaterialTheme.typography.labelMedium)
                            customAllow.forEach { domain ->
                                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                                    Text(domain, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    IconButton(onClick = { onRemoveCustomRule(domain) }) { Icon(Icons.Default.Delete, contentDescription = "Eliminar") }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
