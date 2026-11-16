package com.firewall.dns.domain.engine

import java.net.InetAddress

enum class NgfwAction { ALLOW, BLOCK }

enum class NgfwProtocol(val label: String, val number: Int?) {
    ANY("any", null),
    TCP("tcp", 6),
    UDP("udp", 17)
}

/**
 * Regla de capa 3/4. Formato de texto: `<block|allow> <tcp|udp|any> <ip[/prefijo]|any> <puerto|min-max|any>`.
 */
data class NgfwRule(
    val action: NgfwAction,
    val protocol: NgfwProtocol,
    val network: ByteArray?,
    val prefixLength: Int,
    val portStart: Int,
    val portEnd: Int,
    val text: String
) {
    fun matches(proto: Int, dstIp: ByteArray, dstPort: Int): Boolean {
        protocol.number?.let { if (it != proto) return false }
        if (portStart != 0 || portEnd != 65535) {
            if (dstPort !in portStart..portEnd) return false
        }
        val net = network ?: return true
        return net.size == dstIp.size && prefixMatches(net, dstIp, prefixLength)
    }

    override fun equals(other: Any?): Boolean = other is NgfwRule && other.text == text

    override fun hashCode(): Int = text.hashCode()

    companion object {
        fun parse(raw: String): NgfwRule? {
            val parts = raw.trim().lowercase().split(Regex("\\s+"))
            if (parts.size != 4) return null

            val action = when (parts[0]) {
                "block" -> NgfwAction.BLOCK
                "allow" -> NgfwAction.ALLOW
                else -> return null
            }
            val protocol = NgfwProtocol.values().firstOrNull { it.label == parts[1] } ?: return null

            var network: ByteArray? = null
            var prefix = 0
            if (parts[2] != "any") {
                val addr = parts[2].substringBefore('/')
                if (!isIpLiteral(addr)) return null
                val bytes = InetAddress.getByName(addr).address
                prefix = if (parts[2].contains('/')) {
                    parts[2].substringAfter('/').toIntOrNull() ?: return null
                } else {
                    bytes.size * 8
                }
                if (prefix !in 0..bytes.size * 8) return null
                network = bytes
            }

            var start = 0
            var end = 65535
            if (parts[3] != "any") {
                val lo = parts[3].substringBefore('-').toIntOrNull() ?: return null
                val hi = if (parts[3].contains('-')) {
                    parts[3].substringAfter('-').toIntOrNull() ?: return null
                } else lo
                if (lo !in 0..65535 || hi !in lo..65535) return null
                start = lo
                end = hi
            }

            val canonical = parts.joinToString(" ")
            return NgfwRule(action, protocol, network, prefix, start, end, canonical)
        }

        // Evita resolver nombres de host: solo se aceptan IPv4/IPv6 literales.
        private fun isIpLiteral(value: String): Boolean {
            val v4 = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$").matchEntire(value)
            if (v4 != null) return v4.groupValues.drop(1).all { it.toInt() in 0..255 }
            return value.contains(':') && value.all { it.isDigit() || it in 'a'..'f' || it == ':' || it == '.' }
        }

        private fun prefixMatches(net: ByteArray, ip: ByteArray, prefix: Int): Boolean {
            val fullBytes = prefix / 8
            for (i in 0 until fullBytes) if (net[i] != ip[i]) return false
            val rem = prefix % 8
            if (rem == 0) return true
            val mask = (0xFF shl (8 - rem)) and 0xFF
            return (net[fullBytes].toInt() and mask) == (ip[fullBytes].toInt() and mask)
        }
    }
}

object NgfwRuleEngine {

    /** Devuelve la primera regla que coincide; null si ninguna aplica (se permite). */
    fun firstMatch(rules: List<NgfwRule>, proto: Int, dstIp: String, dstPort: Int): NgfwRule? {
        val bytes = parseIp(dstIp) ?: return null
        return rules.firstOrNull { it.matches(proto, bytes, dstPort) }
    }

    fun parseIp(value: String): ByteArray? {
        val clean = value.trim().removePrefix("[").removeSuffix("]").substringBefore('%')
        if (clean.isEmpty() || !(clean.contains(':') || clean.all { it.isDigit() || it == '.' })) return null
        return try {
            InetAddress.getByName(clean).address
        } catch (_: Exception) {
            null
        }
    }

    /** Separa "ip:puerto" o "[ipv6]:puerto". */
    fun splitHostPort(value: String?): Pair<String, Int>? {
        if (value.isNullOrEmpty()) return null
        val idx = value.lastIndexOf(':')
        if (idx <= 0) return null
        val port = value.substring(idx + 1).toIntOrNull() ?: return null
        return value.substring(0, idx).removePrefix("[").removeSuffix("]") to port
    }
}
