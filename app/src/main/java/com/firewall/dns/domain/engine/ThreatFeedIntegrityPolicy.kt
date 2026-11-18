package com.firewall.dns.domain.engine

import java.security.MessageDigest

/**
 * Validates the minimum integrity requirements for downloaded DNS feeds.
 * A digest is an audit fingerprint, not a publisher signature or proof of authenticity.
 */
object ThreatFeedIntegrityPolicy {
    fun validateSource(payloadBytes: Int, parsedRuleCount: Int): String? {
        if (payloadBytes <= 0) return "La fuente está vacía"
        if (parsedRuleCount <= 0) return "La fuente no contiene reglas DNS válidas"
        return null
    }

    fun sha256(payload: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(payload)
            .joinToString("") { byte -> "%02x".format(byte) }
}
