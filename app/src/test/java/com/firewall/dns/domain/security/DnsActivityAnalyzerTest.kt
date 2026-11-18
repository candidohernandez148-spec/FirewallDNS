package com.firewall.dns.domain.security

import com.firewall.dns.domain.model.DnsLogEntry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsActivityAnalyzerTest {
    @Test
    fun ordinarySmallHistoryHasLowRiskAndNoFindings() {
        val logs = listOf(
            entry("www.example.com", blocked = false, app = "Browser"),
            entry("api.example.com", blocked = false, app = "Browser"),
            entry("cdn.example.com", blocked = false, app = "Browser")
        )

        val result = DnsActivityAnalyzer.assess(logs)

        assertEquals(DnsRiskLevel.LOW, result.level)
        assertTrue(result.findings.isEmpty())
        assertEquals(3, result.analyzedEvents)
    }

    @Test
    fun repeatedBlockedDomainProducesEvidenceAndMediumRisk() {
        val logs = (1..5).map { entry("tracker.example", blocked = true, app = "Browser") }

        val result = DnsActivityAnalyzer.assess(logs)

        assertEquals(DnsRiskLevel.MEDIUM, result.level)
        assertEquals(1, result.findings.size)
        assertTrue(result.findings.first().contains("5 veces"))
    }

    @Test
    fun multipleSignalsRaiseRiskButNeverModifyDnsDecisions() {
        val logs = buildList {
            (1..26).forEach { add(entry("site$it.example", blocked = false, app = "Test app")) }
            (1..5).forEach { add(entry("tracker.example", blocked = true, app = "Test app")) }
        }

        val result = DnsActivityAnalyzer.assess(logs)

        assertEquals(DnsRiskLevel.HIGH, result.level)
        assertEquals(2, result.findings.size)
    }

    private fun entry(domain: String, blocked: Boolean, app: String) = DnsLogEntry(
        id = 1L,
        timestamp = "17/11 12:00:00",
        domain = domain,
        queryType = "A",
        isBlocked = blocked,
        reason = if (blocked) "Lista de bloqueo" else "Permitido",
        appName = app
    )
}
