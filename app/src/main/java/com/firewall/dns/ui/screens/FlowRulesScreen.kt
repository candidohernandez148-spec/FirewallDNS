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
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.firewalldns.engine.core.FlowProtocol
import com.firewalldns.engine.core.NetworkFlowRule
import com.firewalldns.engine.core.PolicyAction

@Composable
fun FlowRulesScreen(
    rules: List<NetworkFlowRule>,
    onAdd: (String, FlowProtocol?, Int?, String?, PolicyAction) -> Unit,
    onRemove: (String) -> Unit
) {
    var cidr by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("") }
    var appPackage by remember { mutableStateOf("") }
    var protocol by remember { mutableStateOf("Todos") }
    var action by remember { mutableStateOf(PolicyAction.BLOCK) }
    var error by remember { mutableStateOf("") }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(18.dp)) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                    Text("Control de flujos TUN", style = MaterialTheme.typography.titleLarge)
                    Text(
                        "Crea reglas para conexiones TCP, UDP o ICMP. Se aplican a flujos nuevos y se conservan al reiniciar.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedTextField(
                        value = cidr, onValueChange = { cidr = it; error = "" },
                        modifier = Modifier.fillMaxWidth(), singleLine = true,
                        label = { Text("IP o red CIDR (ej. 192.0.2.0/24)") }
                    )
                    OutlinedTextField(
                        value = port, onValueChange = { port = it.filter(Char::isDigit).take(5); error = "" },
                        modifier = Modifier.fillMaxWidth(), singleLine = true,
                        label = { Text("Puerto destino (opcional)") }
                    )
                    OutlinedTextField(
                        value = appPackage, onValueChange = { appPackage = it; error = "" },
                        modifier = Modifier.fillMaxWidth(), singleLine = true,
                        label = { Text("Paquete de aplicación (opcional)") }
                    )
                    Text("Protocolo", style = MaterialTheme.typography.labelLarge)
                    Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                        listOf("Todos", "TCP", "UDP", "ICMP").forEach { value ->
                            FilterChip(selected = protocol == value, onClick = { protocol = value },
                                label = { Text(value) })
                        }
                    }
                    Text("Acción", style = MaterialTheme.typography.labelLarge)
                    Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                        listOf(
                            PolicyAction.ALLOW to "Permitir",
                            PolicyAction.OBSERVE to "Observar",
                            PolicyAction.BLOCK to "Rechazar"
                        ).forEach { (value, label) ->
                            FilterChip(selected = action == value, onClick = { action = value },
                                label = { Text(label) })
                        }
                    }
                    if (error.isNotBlank()) {
                        Text(error, color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall)
                    }
                    Button(
                        onClick = {
                            val parsedPort = port.toIntOrNull()
                            if (port.isNotBlank() && (parsedPort == null || parsedPort !in 1..65535)) {
                                error = "El puerto debe estar entre 1 y 65535."
                            } else if (cidr.isBlank()) {
                                error = "Indica una IP o red CIDR."
                            } else {
                                onAdd(cidr, when (protocol) {
                                    "TCP" -> FlowProtocol.TCP
                                    "UDP" -> FlowProtocol.UDP
                                    "ICMP" -> FlowProtocol.ICMP
                                    else -> null
                                }, parsedPort, appPackage.takeIf { it.isNotBlank() }, action)
                                cidr = ""; port = ""; appPackage = ""; error = ""
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("Guardar regla") }
                }
            }
        }
        item {
            Text("Reglas activas · ${rules.size}", style = MaterialTheme.typography.titleMedium)
        }
        if (rules.isEmpty()) {
            item {
                Text("No hay reglas personalizadas de flujos. El comportamiento predeterminado del motor se mantiene.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        items(rules, key = { it.id }) { rule ->
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp)) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        when (rule.action) {
                            PolicyAction.ALLOW -> "PERMITIR"
                            PolicyAction.OBSERVE -> "OBSERVAR"
                            PolicyAction.BLOCK -> "RECHAZAR"
                        },
                        style = MaterialTheme.typography.labelLarge,
                        color = when (rule.action) {
                            PolicyAction.ALLOW -> MaterialTheme.colorScheme.primary
                            PolicyAction.OBSERVE -> MaterialTheme.colorScheme.tertiary
                            PolicyAction.BLOCK -> MaterialTheme.colorScheme.error
                        }
                    )
                    Text(rule.destinationCidr ?: "Cualquier destino", style = MaterialTheme.typography.titleSmall)
                    Text(
                        listOfNotNull(rule.protocol?.name ?: "Todos los protocolos",
                            rule.destinationPort?.let { "Puerto $it" },
                            rule.appPackage).joinToString(" · "),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    TextButton(onClick = { onRemove(rule.id) }) { Text("Eliminar regla") }
                }
            }
        }
        item {
            Text(
                "Los rechazos estructurales del motor (paquetes inválidos, sesiones inexistentes y límites de seguridad) no se pueden convertir en permisos.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
