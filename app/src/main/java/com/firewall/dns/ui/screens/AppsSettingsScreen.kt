package com.firewall.dns.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.platform.LocalContext
import androidx.core.graphics.drawable.toBitmap
import androidx.compose.ui.graphics.asImageBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.firewall.dns.domain.model.AppInfoItem
import com.firewall.dns.domain.model.FirewallStats

@Composable
fun AppsSettingsScreen(
    stats: FirewallStats,
    apps: List<AppInfoItem>,
    excludedPackages: Set<String>,
    blockedApps: Set<String>,
    onToggleBlockedApp: (AppInfoItem) -> Unit,
    appSearch: String,
    onAppSearchChange: (String) -> Unit,
    onToggleExcludedApp: (String) -> Unit,
    onOpenBatteryOpt: () -> Unit,
    onOpenVpnSettings: () -> Unit
) {
    val firestackActive = stats.isRunning && stats.engine.contains("Firestack/gVisor", ignoreCase = true)
    val dnsOnlyFallback = stats.isRunning && stats.engine.contains("DNS fallback", ignoreCase = true)

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 12.dp, vertical = 9.dp),
        contentPadding = PaddingValues(bottom = 12.dp),
        verticalArrangement = Arrangement.spacedBy(9.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Configuración", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Text("Ajustes de tu protección", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Acceso y continuidad", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    Text("Opciones del sistema para mantener la VPN disponible.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Surface(
                        modifier = Modifier.fillMaxWidth().clickable(onClick = onOpenBatteryOpt),
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant
                    ) {
                        Column(Modifier.padding(14.dp)) {
                            Text("Optimización de batería", fontWeight = FontWeight.SemiBold)
                            Text("Configurar restricciones del sistema", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    Surface(
                        modifier = Modifier.fillMaxWidth().clickable(onClick = onOpenVpnSettings),
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant
                    ) {
                        Column(Modifier.padding(14.dp)) {
                            Text("VPN siempre activa", fontWeight = FontWeight.SemiBold)
                            Text("Abrir los ajustes de VPN de Android", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
        }

        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Aplicaciones", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Text("Excluye apps del filtrado o bloquea su acceso a Internet.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (dnsOnlyFallback) {
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.tertiaryContainer
                    ) {
                        Text(
                            "El motor de respaldo solo filtra consultas DNS. Las reglas por aplicación no bloquean conexiones TCP/UDP/ICMP mientras este modo esté activo.",
                            modifier = Modifier.padding(14.dp),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onTertiaryContainer
                        )
                    }
                }
                OutlinedTextField(
                    value = appSearch,
                    onValueChange = onAppSearchChange,
                    placeholder = { Text("Buscar aplicaciones") },
                    singleLine = true,
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }

        if (apps.isEmpty()) {
            item {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(18.dp),
                    color = MaterialTheme.colorScheme.surface
                ) {
                    Text(
                        "No se encontraron aplicaciones.",
                        modifier = Modifier.padding(18.dp),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            items(apps, key = { it.packageName }) { app ->
                val excluded = excludedPackages.contains(app.packageName)
                val internetBlocked = blockedApps.contains(app.packageName)

                val chipText = when {
                    excluded -> "Excluida"
                    internetBlocked && !firestackActive -> "Regla guardada"
                    internetBlocked -> "Sin internet"
                    else -> "Protegida"
                }
                val chipColor = when {
                    excluded -> MaterialTheme.colorScheme.tertiary
                    internetBlocked -> MaterialTheme.colorScheme.error
                    else -> MaterialTheme.colorScheme.secondary
                }

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(15.dp),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                ) {
                    Column(modifier = Modifier.padding(11.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            AppIcon(app)
                            Column(modifier = Modifier.weight(1f).padding(start = 9.dp)) {
                                Text(app.label, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(
                                    "UID ${app.uid} · ${app.packageName}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                if (app.isSystemApp) {
                                    Text(
                                        "Aplicación del sistema",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.tertiary
                                    )
                                }
                            }
                            StatusChip(text = chipText, color = chipColor)
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("Excluir del filtrado", modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                            Switch(
                                checked = excluded,
                                onCheckedChange = { wantExclude ->
                                    if (wantExclude && internetBlocked) onToggleBlockedApp(app)
                                    onToggleExcludedApp(app.packageName)
                                }
                            )
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                when {
                                    excluded -> "Internet bloqueado (desactiva excluir)"
                                    internetBlocked && !firestackActive -> "Regla guardada; el bloqueo total requiere Firestack activo"
                                    internetBlocked -> "Internet bloqueado"
                                    else -> "Internet permitido"
                                },
                                modifier = Modifier.weight(1f),
                                style = MaterialTheme.typography.bodyMedium,
                                color = if (excluded) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface
                            )
                            Switch(
                                checked = !excluded && internetBlocked,
                                enabled = !excluded,
                                onCheckedChange = { onToggleBlockedApp(app) }
                            )
                        }
                    }
                }
            }
        }

        item {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                color = MaterialTheme.colorScheme.primaryContainer
            ) {
                Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Text("Firewall DNS", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onPrimaryContainer)
                    Text("Protección DNS local para tu dispositivo.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onPrimaryContainer)
                    Text("Desarrollado por Candido y Elizabeth · Versión 1.0", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.75f))
                }
            }
        }
    }
}

@Composable
private fun AppIcon(app: AppInfoItem) {
    val context = LocalContext.current
    val icon by produceState(initialValue = app.icon, key1 = app.packageName) {
        value = withContext(Dispatchers.IO) {
            try {
                context.packageManager.getApplicationIcon(app.packageName)
                    .toBitmap(96, 96)
                    .asImageBitmap()
            } catch (_: Exception) {
                null
            }
        }
    }
    val loadedIcon = icon
    val shape = RoundedCornerShape(12.dp)
    val modifier = Modifier.size(40.dp).clip(shape)
    if (loadedIcon != null) {
        Image(bitmap = loadedIcon, contentDescription = app.label, modifier = modifier)
    } else {
        Box(modifier = modifier.background(MaterialTheme.colorScheme.primaryContainer), contentAlignment = Alignment.Center) {
            Text(
                app.label.take(1).uppercase(),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
private fun StatusChip(text: String, color: Color) {
    Surface(shape = CircleShape, color = color.copy(alpha = 0.14f)) {
        Text(
            text,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
            style = MaterialTheme.typography.labelMedium,
            color = color
        )
    }
}
