package com.firewall.dns.domain.ai

import com.firewall.dns.data.local.BlocklistSnapshot
import com.firewall.dns.domain.model.DnsLogEntry
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalAiEvidenceBuilderTest {
    @Test
    fun summarizesUidActionsAndSeparatesListMembershipFromRecordedDecision() {
        val logs = listOf(
            event(42, "ads.example", "BLOCK"),
            event(42, "api.example", "ALLOW"),
            event(42, "metrics.ads.example", "OBSERVE")
        )
        val lists = BlocklistSnapshot(
            blocked = setOf("ads.example"),
            exceptions = emptySet(),
            threatDomainsByCategory = emptyMap()
        )

        val prompt = LocalAiEvidenceBuilder.buildPrompt(logs, lists)

        assertTrue(prompt.contains("UID 42"))
        assertTrue(prompt.contains("BLOCK 1"))
        assertTrue(prompt.contains("ALLOW 1"))
        assertTrue(prompt.contains("OBSERVE 1"))
        assertTrue(prompt.contains("coincide con lista BLOCK"))
        assertTrue(prompt.contains("sin coincidencia directa en listas consultadas"))
    }

    @Test
    fun ignoresInvalidUidForPerAppSummaryButKeepsItInRecentEvents() {
        val prompt = LocalAiEvidenceBuilder.buildPrompt(
            listOf(event(-1, "dns.local", "ALLOW")),
            BlocklistSnapshot(emptySet(), emptySet(), emptyMap())
        )

        assertTrue(!prompt.contains("UID -1 | aplicación"))
        assertTrue(prompt.contains("UID -1 | ALLOW | dns.local"))
    }

    @Test
    fun treatsUnknownActionsAsOtherInsteadOfAssumingAllow() {
        val prompt = LocalAiEvidenceBuilder.buildPrompt(
            listOf(event(7, "host.example", "UNKNOWN")),
            BlocklistSnapshot(emptySet(), emptySet(), emptyMap())
        )

        assertTrue(prompt.contains("otros 1"))
        assertTrue(prompt.contains("ALLOW 0"))
    }

    private fun event(uid: Int, domain: String, action: String) = DnsLogEntry(
        id = uid.toLong() + domain.hashCode(),
        timestamp = "22/11 12:00:00",
        domain = domain,
        queryType = "A",
        isBlocked = action == "BLOCK",
        reason = "test",
        appName = "Test App",
        uid = uid,
        decisionAction = action
    )
}
