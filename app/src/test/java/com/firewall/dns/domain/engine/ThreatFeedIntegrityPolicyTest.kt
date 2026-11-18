package com.firewall.dns.domain.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatFeedIntegrityPolicyTest {
    @Test
    fun rejectsEmptyPayload() {
        assertEquals(
            "La fuente está vacía",
            ThreatFeedIntegrityPolicy.validateSource(payloadBytes = 0, parsedRuleCount = 0)
        )
    }

    @Test
    fun rejectsNonEmptyPayloadWithoutDnsRules() {
        assertEquals(
            "La fuente no contiene reglas DNS válidas",
            ThreatFeedIntegrityPolicy.validateSource(payloadBytes = 128, parsedRuleCount = 0)
        )
    }

    @Test
    fun acceptsPayloadWithAtLeastOneParsedDnsRule() {
        assertNull(ThreatFeedIntegrityPolicy.validateSource(payloadBytes = 128, parsedRuleCount = 1))
    }

    @Test
    fun sha256IsDeterministicAndProducesFullDigest() {
        val first = ThreatFeedIntegrityPolicy.sha256("||example.com^".toByteArray())
        val second = ThreatFeedIntegrityPolicy.sha256("||example.com^".toByteArray())

        assertEquals(first, second)
        assertEquals(64, first.length)
        assertTrue(first.all { it in '0'..'9' || it in 'a'..'f' })
        assertFalse(first == ThreatFeedIntegrityPolicy.sha256("||other.example^".toByteArray()))
    }
}
