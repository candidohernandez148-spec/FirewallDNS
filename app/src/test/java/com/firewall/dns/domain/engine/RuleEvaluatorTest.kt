package com.firewall.dns.domain.engine

import org.junit.Assert.assertEquals
import org.junit.Test

class RuleEvaluatorTest {
    private val dollar = 36.toChar().toString()

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

    @Test
    fun parsesDnsSafeDomainRulesAndImportantModifier() {
        assertEquals(
            RuleEvaluator.AdblockParseResult("tracker.example", false),
            RuleEvaluator.parseAdblockLine("||tracker.example^")
        )
        assertEquals(
            RuleEvaluator.AdblockParseResult("tracker.example", true),
            RuleEvaluator.parseAdblockLine("@@||tracker.example^")
        )
        assertEquals(
            RuleEvaluator.AdblockParseResult("tracker.example", false, isImportant = true),
            RuleEvaluator.parseAdblockLine("||tracker.example^" + dollar + "important")
        )
        assertEquals(
            RuleEvaluator.AdblockParseResult("tracker.example", true, isImportant = true),
            RuleEvaluator.parseAdblockLine("@@||tracker.example^" + dollar + "important")
        )
        assertEquals(
            RuleEvaluator.AdblockParseResult("tracker.example", true, includeSubdomains = false),
            RuleEvaluator.parseAdblockLine("@@tracker.example")
        )
        assertEquals(
            RuleEvaluator.AdblockParseResult("tracker.example", false, includeSubdomains = false),
            RuleEvaluator.parseAdblockLine("tracker.example")
        )
        assertEquals(
            RuleEvaluator.AdblockParseResult("tracker.example", false, includeSubdomains = false),
            RuleEvaluator.parseAdblockLine("0.0.0.0 tracker.example # local sinkhole")
        )
    }

    @Test
    fun parsesEveryDomainFromMultiAliasHostsLines() {
        assertEquals(
            listOf(
                RuleEvaluator.AdblockParseResult("tracker.example", false, includeSubdomains = false),
                RuleEvaluator.AdblockParseResult("www.tracker.example", false, includeSubdomains = false),
                RuleEvaluator.AdblockParseResult("cdn.tracker.example", false, includeSubdomains = false)
            ),
            RuleEvaluator.parseAdblockLineEntries(
                "0.0.0.0 tracker.example www.tracker.example cdn.tracker.example"
            )
        )
        assertEquals(
            listOf(RuleEvaluator.AdblockParseResult("tracker.example", false, includeSubdomains = false)),
            RuleEvaluator.parseAdblockLineEntries("::1 tracker.example")
        )
    }

    @Test
    fun rejectsAdblockOptionsWhoseSemanticsAreNotImplemented() {
        val unsupported = listOf(
            "third-party",
            "domain=publisher.example",
            "badfilter",
            "dnsrewrite=NOERROR",
            "important,domain=publisher.example"
        )
        unsupported.forEach { option ->
            val rule = "||tracker.example^" + dollar + option
            assertEquals("Unsupported option: " + option, null, RuleEvaluator.parseAdblockLine(rule))
        }
    }

    @Test
    fun rejectsUrlAndWildcardRulesInsteadOfOverblockingWholeDomains() {
        assertEquals(null, RuleEvaluator.parseAdblockLine("||example.com/ads.js"))
        assertEquals(null, RuleEvaluator.parseAdblockLine("||*.example.com^"))
        assertEquals(null, RuleEvaluator.parseAdblockLine("example.com/path"))
    }

    @Test
    fun importantBlockOverridesNormalExceptionButNotManualRules() {
        val importantBlock = RuleEvaluator.evaluate(
            domain = "ads.example.com",
            customAllow = emptySet(),
            customBlock = emptySet(),
            hostExceptions = setOf("example.com"),
            hostBlock = emptySet(),
            importantBlock = setOf("example.com")
        )
        assertEquals(true, importantBlock.first)
        assertEquals("Adblock importante ||^", importantBlock.second)

        val manualBlock = RuleEvaluator.evaluate(
            domain = "ads.example.com",
            customAllow = emptySet(),
            customBlock = setOf("example.com"),
            hostExceptions = emptySet(),
            hostBlock = emptySet(),
            importantExceptions = setOf("example.com")
        )
        assertEquals(true, manualBlock.first)
        assertEquals("Regla propia", manualBlock.second)

        val manualAllow = RuleEvaluator.evaluate(
            domain = "ads.example.com",
            customAllow = setOf("example.com"),
            customBlock = emptySet(),
            hostExceptions = emptySet(),
            hostBlock = emptySet(),
            importantBlock = setOf("example.com")
        )
        assertEquals(false, manualAllow.first)
        assertEquals("Lista blanca", manualAllow.second)
    }

    @Test
    fun importantExceptionOverridesImportantBlock() {
        val result = RuleEvaluator.evaluate(
            domain = "ads.example.com",
            customAllow = emptySet(),
            customBlock = emptySet(),
            hostExceptions = emptySet(),
            hostBlock = emptySet(),
            importantExceptions = setOf("example.com"),
            importantBlock = setOf("example.com")
        )
        assertEquals(false, result.first)
        assertEquals("Excepción importante @@||", result.second)
    }

    @Test
    fun bareDomainRulesMatchOnlyTheExactHostname() {
        val exact = RuleEvaluator.evaluate(
            domain = "tracker.example",
            customAllow = emptySet(),
            customBlock = emptySet(),
            hostExceptions = emptySet(),
            hostBlock = emptySet(),
            exactBlock = setOf("tracker.example")
        )
        val subdomain = RuleEvaluator.evaluate(
            domain = "cdn.tracker.example",
            customAllow = emptySet(),
            customBlock = emptySet(),
            hostExceptions = emptySet(),
            hostBlock = emptySet(),
            exactBlock = setOf("tracker.example")
        )
        assertEquals(true, exact.first)
        assertEquals("Adblock exacto", exact.second)
        assertEquals(false, subdomain.first)
    }


    @Test
    fun importantExactRuleDoesNotMatchSubdomains() {
        val exact = RuleEvaluator.evaluate(
            domain = "tracker.example",
            customAllow = emptySet(),
            customBlock = emptySet(),
            hostExceptions = emptySet(),
            hostBlock = emptySet(),
            importantExactBlock = setOf("tracker.example")
        )
        val subdomain = RuleEvaluator.evaluate(
            domain = "cdn.tracker.example",
            customAllow = emptySet(),
            customBlock = emptySet(),
            hostExceptions = emptySet(),
            hostBlock = emptySet(),
            importantExactBlock = setOf("tracker.example")
        )
        assertEquals(true, exact.first)
        assertEquals("Adblock importante exacto", exact.second)
        assertEquals(false, subdomain.first)
    }

}
