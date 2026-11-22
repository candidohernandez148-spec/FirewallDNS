package com.firewalldns.engine.android

import java.net.InetAddress

/**
 * Prevents applications from bypassing the virtual DNS endpoints by sending
 * cleartext DNS directly to public or router resolvers. Firestack's own DNS53
 * upstream sockets are created outside the TUN and are not evaluated here.
 */
object DnsPortGuard {
    private val fakeDnsAddresses = setOf(
        "10.10.10.1",
        "fd00:10:10::1",
    ).map { InetAddress.getByName(it).address.contentToString() }.toSet()

    fun shouldBlock(protocolNumber: Int, destinationAddress: String, destinationPort: Int): Boolean {
        if (protocolNumber != 6 && protocolNumber != 17) return false
        if (destinationPort != 53) return false
        val normalized = normalizeAddress(destinationAddress)
        return normalized !in fakeDnsAddresses
    }

    private fun normalizeAddress(value: String): String? {
        val unscoped = value.substringBefore('%').removePrefix("[").removeSuffix("]")
        return runCatching { InetAddress.getByName(unscoped).address.contentToString() }
            .getOrNull()
    }
}
