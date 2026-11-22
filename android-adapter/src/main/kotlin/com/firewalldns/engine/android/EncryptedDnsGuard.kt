package com.firewalldns.engine.android

/**
 * Detects common encrypted-DNS transports that would otherwise bypass
 * plaintext DNS domain policy. DoH detection is limited to known endpoint
 * hostnames supplied by Firestack's DNS-to-flow correlation.
 */
object EncryptedDnsGuard {
    private val knownDohEndpoints = setOf(
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "dns.google",
        "dns.quad9.net",
        "doh.opendns.com",
        "dns.nextdns.io",
        "dns.adguard-dns.com",
        "doh.cleanbrowsing.org",
        "dns0.eu",
        "doh.dns.sb",
        "doh.libredns.gr",
    )

    fun shouldBlockPort(protocolNumber: Int, destinationPort: Int): Boolean {
        if (protocolNumber != 6 && protocolNumber != 17) return false
        if (destinationPort == 853) return true // DoT and standard DoQ
        return protocolNumber == 17 && destinationPort in setOf(784, 8853)
    }

    fun isKnownDohEndpoint(domain: String): Boolean {
        val normalized = domain.trim().trimEnd('.').lowercase()
        return knownDohEndpoints.any { normalized == it || normalized.endsWith(".$it") }
    }
}
