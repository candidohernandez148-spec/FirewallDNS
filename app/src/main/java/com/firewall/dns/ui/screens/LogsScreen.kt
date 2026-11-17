package com.firewall.dns.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.firewall.dns.domain.model.DnsLogEntry
import com.firewall.dns.domain.model.FirewallStats
import com.firewall.dns.domain.model.TrafficPoint

@Composable
fun LogsScreen(
    stats: FirewallStats,
    logs: List<DnsLogEntry>,
    traffic: List<TrafficPoint>,
    otherVpnActive: Boolean,
    searchQuery: String,
    onlyBlocked: Boolean,
    onSearchQueryChange: (String) -> Unit,
    onToggleOnlyBlocked: () -> Unit,
    onClearLogs: () -> Unit,
    onToggleRule: (DnsLogEntry) -> Unit
) {
    val total = stats.totalAllowed + stats.totalBlocked
    val blockRate = if (total > 0) stats.totalBlocked * 100f / total else 0f
    val topBlocked = remember(logs, searchQuery) {
        if (searchQuery.isNotBlank()) emptyList()
        else logs.filter { it.isBlocked }.groupingBy { it.domain }.eachCount().entries
            .sortedByDescending { it.value }.take(3)
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(20.dp),
                color = if (stats.isRunning) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Box(
                        Modifier.size(10.dp).background(
                            if (stats.isRunning) Color(0xFF22C55E) else MaterialTheme.colorScheme.outline, CircleShape
                        )
                    )
                    Column(Modifier.weight(1f)) {
                        Text(
                            if (stats.isRunning) "Firewall activo" else "Firewall apagado",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            when {
                                !stats.isRunning -> "Enciende el interruptor superior para proteger tu dispositivo"
                                stats.engine == "Firestack" -> "Motor: Firestack (local) · ${stats.networkType}"
                                else -> "Motor: Respaldo DNS · ${stats.networkType}"
                            },
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }

        if (otherVpnActive) {
            item {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    color = MaterialTheme.colorScheme.errorContainer
                ) {
                    Column(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("Otra VPN está activa", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onErrorContainer)
                        Text(
                            "Otra app VPN (como Outline) ocupa el permiso de red del sistema. Desactívala en Ajustes de VPN y vuelve a encender el firewall.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Tráfico en tiempo real", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                            Text("Últimos ${traffic.size * 2} s", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Legend("Permitidos", ALLOWED_COLOR)
                        Spacer(Modifier.width(12.dp))
                        Legend("Bloqueados", BLOCKED_COLOR)
                    }
                    TrafficChart(traffic, Modifier.fillMaxWidth().height(110.dp))
                }
            }
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ActivityMetric("Bloqueados", stats.totalBlocked.toString(), BLOCKED_COLOR, Modifier.weight(1f))
                ActivityMetric("Permitidos", stats.totalAllowed.toString(), ALLOWED_COLOR, Modifier.weight(1f))
                ActivityMetric("Bloqueo", "${"%.0f".format(blockRate)}%", MaterialTheme.colorScheme.primary, Modifier.weight(1f))
                ActivityMetric("Reglas", compactNumber(stats.loadedRulesCount), MaterialTheme.colorScheme.onSurfaceVariant, Modifier.weight(1f))
            }
        }

        if (topBlocked.isNotEmpty()) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                ) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("Más bloqueados", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                        val max = topBlocked.first().value.coerceAtLeast(1)
                        topBlocked.forEach { (domain, count) ->
                            Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                Row {
                                    Text(domain, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    Text("$count", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold, color = BLOCKED_COLOR)
                                }
                                Box(Modifier.fillMaxWidth().height(4.dp).background(MaterialTheme.colorScheme.surfaceVariant, CircleShape)) {
                                    Box(Modifier.fillMaxHeight().fillMaxWidth(count.toFloat() / max).background(BLOCKED_COLOR, CircleShape))
                                }
                            }
                        }
                    }
                }
            }
        }

        item {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Surface(
                    modifier = Modifier.weight(1f).height(40.dp),
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.surfaceVariant
                ) {
                    Row(
                        Modifier.padding(horizontal = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(Icons.Default.Search, contentDescription = "Buscar", modifier = Modifier.size(18.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                        Box(Modifier.weight(1f), contentAlignment = Alignment.CenterStart) {
                            if (searchQuery.isEmpty()) {
                                Text("Buscar dominio o app", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            BasicTextField(
                                value = searchQuery,
                                onValueChange = onSearchQueryChange,
                                singleLine = true,
                                textStyle = TextStyle(color = LocalContentColor.current, fontSize = 14.sp),
                                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                    }
                }
                FilterChip(
                    selected = onlyBlocked,
                    onClick = onToggleOnlyBlocked,
                    label = { Text("Bloqueados", fontSize = 12.sp) }
                )
                IconButton(onClick = onClearLogs, modifier = Modifier.size(36.dp)) {
                    Icon(Icons.Default.Delete, contentDescription = "Limpiar actividad", modifier = Modifier.size(20.dp))
                }
            }
        }

        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("Actividad de red", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text("${logs.size} eventos", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        if (logs.isEmpty()) {
            item {
                Column(
                    Modifier.fillMaxWidth().padding(vertical = 32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text("Sin actividad todavía", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(
                        text = if (stats.isRunning) "Las consultas DNS y conexiones de cada app aparecerán aquí." else "Activa la protección para empezar a registrar consultas.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            items(logs, key = { it.id }) { entry ->
                ActivityEntry(entry = entry, onToggleRule = { onToggleRule(entry) })
            }
        }
    }
}

private val ALLOWED_COLOR = Color(0xFF22C55E)
private val BLOCKED_COLOR = Color(0xFFEF4444)

private fun compactNumber(n: Int): String = if (n >= 1000) "${"%.1f".format(n / 1000f)}k" else n.toString()

@Composable
private fun Legend(label: String, color: Color) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(5.dp)) {
        Box(Modifier.size(8.dp).background(color, CircleShape))
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun TrafficChart(points: List<TrafficPoint>, modifier: Modifier = Modifier) {
    val grid = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)
    Canvas(modifier) {
        val max = (points.maxOfOrNull { maxOf(it.allowed, it.blocked) } ?: 0).coerceAtLeast(4).toFloat()
        repeat(4) { i ->
            val y = size.height * i / 3f
            drawLine(grid, Offset(0f, y), Offset(size.width, y), strokeWidth = 1f)
        }
        if (points.size < 2) return@Canvas
        val stepX = size.width / (points.size - 1)
        fun series(selector: (TrafficPoint) -> Int, color: Color) {
            val line = Path()
            points.forEachIndexed { i, p ->
                val x = i * stepX
                val y = size.height - size.height * selector(p) / max * 0.92f
                if (i == 0) line.moveTo(x, y) else line.lineTo(x, y)
            }
            val fill = Path().apply {
                addPath(line)
                lineTo(size.width, size.height)
                lineTo(0f, size.height)
                close()
            }
            drawPath(fill, Brush.verticalGradient(listOf(color.copy(alpha = 0.28f), Color.Transparent)))
            drawPath(line, color, style = Stroke(width = 3f))
        }
        series({ it.allowed }, ALLOWED_COLOR)
        series({ it.blocked }, BLOCKED_COLOR)
    }
}

@Composable
private fun ActivityMetric(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 6.dp, vertical = 10.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(3.dp)
        ) {
            Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, color = color)
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
        }
    }
}

@Composable
private fun ActivityEntry(entry: DnsLogEntry, onToggleRule: () -> Unit) {
    val blocked = entry.isBlocked
    val badgeColor = if (blocked) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.secondaryContainer
    val badgeTextColor = if (blocked) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSecondaryContainer

    // Solo mostrar acción de regla de dominio cuando es un dominio real y no un bloqueo completo de app.
    val canToggleDomain = entry.domain.contains('.') &&
        !entry.domain.contains(':') &&
        entry.domain.any { it in 'a'..'z' || it in 'A'..'Z' } &&
        entry.reason != "Internet bloqueado para la app"

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Row(Modifier.height(IntrinsicSize.Min)) {
            Box(Modifier.width(4.dp).fillMaxHeight().background(if (blocked) BLOCKED_COLOR else ALLOWED_COLOR))
            Column(
                modifier = Modifier.weight(1f).padding(start = 12.dp, top = 8.dp, bottom = 4.dp, end = 4.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        entry.domain,
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(entry.timestamp, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.width(8.dp))
                }
                Text(
                    "${entry.appName} · ${entry.queryType} · ${entry.reason}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(shape = CircleShape, color = badgeColor) {
                        Text(
                            if (blocked) "BLOQUEADO" else "PERMITIDO",
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                            color = badgeTextColor,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            fontSize = 10.sp
                        )
                    }
                    Spacer(Modifier.weight(1f))
                    if (canToggleDomain) {
                        TextButton(
                            onClick = onToggleRule,
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                            modifier = Modifier.height(28.dp)
                        ) {
                            Text(if (blocked) "Permitir" else "Bloquear", fontSize = 12.sp)
                        }
                    }
                }
            }
        }
    }
}
