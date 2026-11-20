package com.firewall.dns.domain.engine

/**
 * Resultado de validar un paquete IP completo que transporta TCP o UDP.
 *
 * No procesa fragmentación ni extensiones IPv6: esos paquetes se rechazan
 * antes de leer puertos. No implementa estados TCP ni DNS sobre TCP.
 */
data class ValidatedTunTransportPacket(
    val isIpv6: Boolean,
    val ipHeaderLength: Int,
    val ipTotalLength: Int,
    val protocol: Int,
    val sourceAddress: ByteArray,
    val destinationAddress: ByteArray,
    val sourcePort: Int,
    val destinationPort: Int,
    /** Longitud de cabecera TCP (incluidas opciones) o 8 para UDP. */
    val transportHeaderLength: Int,
    val transportLength: Int,
) {
    val payloadOffset: Int get() = ipHeaderLength + transportHeaderLength
    val payloadLength: Int get() = transportLength - transportHeaderLength
}

/**
 * Validador de capa 3/4 para el límite TUN de FirewallDNS.
 *
 * Requiere un paquete IP completo (sin bytes sobrantes), cabeceras IPv4/IPv6
 * admitidas y checksum TCP/UDP correcto. IPv4 UDP checksum cero es válido;
 * IPv6 UDP checksum cero y TCP checksum cero siempre son inválidos.
 */
object TunTransportPacketParser {
    private const val IPPROTO_TCP = 6
    private const val IPPROTO_UDP = 17

    fun parse(packet: ByteArray): ValidatedTunTransportPacket? {
        if (packet.isEmpty()) return null
        val version = (packet[0].toInt() ushr 4) and 0x0f

        val isIpv6: Boolean
        val ipHeaderLength: Int
        val totalLength: Int
        val protocol: Int
        val source: ByteArray
        val destination: ByteArray

        when (version) {
            4 -> {
                if (packet.size < 20) return null
                ipHeaderLength = (packet[0].toInt() and 0x0f) * 4
                if (ipHeaderLength !in 20..60 || packet.size < ipHeaderLength) return null
                totalLength = u16(packet, 2)
                if (totalLength != packet.size || totalLength < ipHeaderLength) return null
                // Reserved flag, MF and fragment offset are unsupported; DF is allowed.
                if ((u16(packet, 6) and 0xBFFF) != 0) return null
                if (checksum(packet, 0, ipHeaderLength) != 0) return null
                protocol = packet[9].toInt() and 0xff
                source = packet.copyOfRange(12, 16)
                destination = packet.copyOfRange(16, 20)
                isIpv6 = false
            }
            6 -> {
                if (packet.size < 40) return null
                val payloadLength = u16(packet, 4)
                // Jumbograms (payload length zero) and extension headers are not
                // accepted by this DNS-only ingress path.
                if (payloadLength == 0 || 40 + payloadLength != packet.size) return null
                protocol = packet[6].toInt() and 0xff
                if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) return null
                ipHeaderLength = 40
                totalLength = packet.size
                source = packet.copyOfRange(8, 24)
                destination = packet.copyOfRange(24, 40)
                isIpv6 = true
            }
            else -> return null
        }

        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) return null
        val transportLength = totalLength - ipHeaderLength
        val transportOffset = ipHeaderLength
        if (transportLength < if (protocol == IPPROTO_TCP) 20 else 8) return null

        val transportHeaderLength = if (protocol == IPPROTO_TCP) {
            val headerLength = ((packet[transportOffset + 12].toInt() ushr 4) and 0x0f) * 4
            if (headerLength !in 20..transportLength) return null
            val checksumValue = u16(packet, transportOffset + 16)
            if (checksumValue == 0 || transportChecksum(
                    isIpv6, source, destination, protocol, packet, transportOffset, transportLength
                ) != 0
            ) return null
            headerLength
        } else {
            val udpLength = u16(packet, transportOffset + 4)
            if (udpLength != transportLength || udpLength < 8) return null
            val checksumValue = u16(packet, transportOffset + 6)
            if (isIpv6 && checksumValue == 0) return null
            if (checksumValue != 0 && transportChecksum(
                    isIpv6, source, destination, protocol, packet, transportOffset, transportLength
                ) != 0
            ) return null
            8
        }

        return ValidatedTunTransportPacket(
            isIpv6 = isIpv6,
            ipHeaderLength = ipHeaderLength,
            ipTotalLength = totalLength,
            protocol = protocol,
            sourceAddress = source,
            destinationAddress = destination,
            sourcePort = u16(packet, transportOffset),
            destinationPort = u16(packet, transportOffset + 2),
            transportHeaderLength = transportHeaderLength,
            transportLength = transportLength,
        )
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun checksum(bytes: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += u16(bytes, index).toLong()
            index += 2
        }
        if (index < end) sum += (bytes[index].toInt() and 0xff).toLong() shl 8
        return fold(sum)
    }

    private fun transportChecksum(
        ipv6: Boolean,
        source: ByteArray,
        destination: ByteArray,
        protocol: Int,
        packet: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        var sum = 0L
        for (index in source.indices step 2) {
            sum += (((source[index].toInt() and 0xff) shl 8) or
                (source[index + 1].toInt() and 0xff)).toLong()
            sum += (((destination[index].toInt() and 0xff) shl 8) or
                (destination[index + 1].toInt() and 0xff)).toLong()
        }
        if (ipv6) {
            sum += ((length ushr 16) and 0xffff).toLong()
            sum += (length and 0xffff).toLong()
            sum += protocol.toLong()
        } else {
            sum += protocol.toLong()
            sum += length.toLong()
        }
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += u16(packet, index).toLong()
            index += 2
        }
        if (index < end) sum += (packet[index].toInt() and 0xff).toLong() shl 8
        return fold(sum)
    }

    private fun fold(initial: Long): Int {
        var sum = initial
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv().toInt() and 0xffff
    }
}
