package com.firewall.dns.domain.engine

import org.junit.Assert.assertEquals
import org.junit.Test

class RuleEvaluatorTest {

    @Test
    fun manualAllowOverridesEveryBlockSource() {
        val result = RuleEvaluator.evaluate(
            domain = "ads.example.com",
            customAllow = setOf("example.com"),
            customBlock = setOf("ads.example.com"),
            hostExceptions = emptySet(),
            hostBlock = setOf("example.com")
        )
        assertEquals(false, result.first)
        assertEquals("Lista blanca", result.second)
    }

    @Test
    fun listExceptionOverridesListBlockButNotManualBlock() {
        val exceptionResult = RuleEvaluator.evaluate(
            domain = "img.ads.example.com",
            customAllow = emptySet(),
            customBlock = emptySet(),
            hostExceptions = setOf("example.com"),
            hostBlock = setOf("example.com")
        )
        assertEquals(false, exceptionResult.first)

        val manualBlockResult = RuleEvaluator.evaluate(
            domain = "img.ads.example.com",
            customAllow = emptySet(),
            customBlock = setOf("example.com"),
            hostExceptions = setOf("example.com"),
            hostBlock = setOf("example.com")
        )
        assertEquals(true, manualBlockResult.first)
        assertEquals("Regla propia", manualBlockResult.second)
    }

    @Test
    fun parentDomainMatchesSubdomainsWithoutMatchingSimilarSuffixes() {
        val blocked = RuleEvaluator.evaluate(
            domain = "cdn.ads.example.com",
            customAllow = emptySet(),
            customBlock = emptySet(),
            hostExceptions = emptySet(),
            hostBlock = setOf("example.com")
        )
        val allowed = RuleEvaluator.evaluate(
            domain = "notexample.com",
            customAllow = emptySet(),
            customBlock = emptySet(),
            hostExceptions = emptySet(),
            hostBlock = setOf("example.com")
        )
        assertEquals(true, blocked.first)
        assertEquals(false, allowed.first)
    }
    @Test
    fun builtInThreatDomainsAreIncludedInTheSameRuleEvaluationSnapshot() {
        val result = RuleEvaluator.evaluate(
            domain = "pixel.facebook.com",
            customAllow = emptySet(),
            customBlock = emptySet(),
            hostExceptions = emptySet(),
            hostBlock = BuiltInThreatDomains.domains.toSet()
        )
        assertEquals(true, result.first)
        assertEquals("Adblock ||^", result.second)
    }

    @Test
    fun builtInDomainExceptionsCanOverrideSeededThreatDomains() {
        val result = RuleEvaluator.evaluate(
            domain = "pixel.facebook.com",
            customAllow = emptySet(),
            customBlock = emptySet(),
            hostExceptions = setOf("facebook.com"),
            hostBlock = BuiltInThreatDomains.domains.toSet()
        )
        assertEquals(false, result.first)
        assertEquals("Excepción @@||", result.second)
    }

}
