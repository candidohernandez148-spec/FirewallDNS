package com.firewall.dns.domain.engine

import org.junit.Assert.assertEquals
import org.junit.Test

class LocalAiRuleIntegrationTest {

    private fun evaluate(
        domain: String,
        allow: Set<String> = emptySet(),
        manualBlock: Set<String> = emptySet(),
        aiBlock: Set<String> = setOf("ads.example.com"),
        exceptions: Set<String> = emptySet(),
        importantBlock: Set<String> = emptySet()
    ) = RuleEvaluator.evaluate(
        domain = domain,
        customAllow = allow,
        customBlock = manualBlock,
        hostExceptions = exceptions,
        hostBlock = emptySet(),
        importantBlock = importantBlock,
        aiBlocked = aiBlock
    )

    @Test
    fun aiBlockAppliesToDomainAndSubdomains() {
        assertEquals(true, evaluate("ads.example.com").first)
        assertEquals(true, evaluate("cdn.ads.example.com").first)
        assertEquals("IA local: publicidad/rastreo", evaluate("cdn.ads.example.com").second)
    }

    @Test
    fun explicitUserAllowOverridesAiBlock() {
        assertEquals(false, evaluate("cdn.ads.example.com", allow = setOf("example.com")).first)
        assertEquals("Lista blanca", evaluate("cdn.ads.example.com", allow = setOf("example.com")).second)
    }

    @Test
    fun explicitUserBlockRemainsAuthoritative() {
        assertEquals("Regla propia", evaluate("ads.example.com", manualBlock = setOf("ads.example.com")).second)
    }

    @Test
    fun downloadedExceptionsOverrideAiButImportantBlocksRemainHigherPriority() {
        assertEquals(false, evaluate("ads.example.com", exceptions = setOf("example.com")).first)
        assertEquals(true, evaluate("ads.example.com", importantBlock = setOf("example.com")).first)
    }

    @Test
    fun unrelatedDomainsRemainAllowed() {
        assertEquals(false, evaluate("www.example.org").first)
    }
}
