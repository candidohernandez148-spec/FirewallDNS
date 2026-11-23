package com.firewall.dns.domain.ai

import org.junit.Assert.assertEquals
import org.junit.Test

class LocalAiPolicyGateTest {

    private fun suggestion(
        domain: String = "ads.example.com",
        category: LocalAiDomainCategory = LocalAiDomainCategory.ADVERTISING,
        action: LocalAiSuggestedAction = LocalAiSuggestedAction.BLOCK,
        confidence: Float = 0.99f
    ) = LocalAiDomainSuggestion(domain, category, action, confidence)

    @Test
    fun highConfidenceAdvertisingBlockCanBeApplied() {
        assertEquals(
            LocalAiPolicyOutcome.APPLY_AI_BLOCK,
            LocalAiPolicyGate.resolve(suggestion(), emptySet(), emptySet())
        )
    }

    @Test
    fun userAllowOverridesAiBlockIncludingSubdomains() {
        assertEquals(
            LocalAiPolicyOutcome.MANUAL_ALLOW,
            LocalAiPolicyGate.resolve(
                suggestion(domain = "cdn.ads.example.com"),
                setOf("ads.example.com"),
                emptySet()
            )
        )
    }

    @Test
    fun userBlockRemainsAuthoritative() {
        assertEquals(
            LocalAiPolicyOutcome.MANUAL_BLOCK,
            LocalAiPolicyGate.resolve(
                suggestion(action = LocalAiSuggestedAction.ALLOW),
                emptySet(),
                setOf("example.com")
            )
        )
    }

    @Test
    fun lowConfidenceOrOtherCategoryCannotAutoBlock() {
        assertEquals(
            LocalAiPolicyOutcome.OBSERVE_ONLY,
            LocalAiPolicyGate.resolve(suggestion(confidence = 0.91f), emptySet(), emptySet())
        )
        assertEquals(
            LocalAiPolicyOutcome.OBSERVE_ONLY,
            LocalAiPolicyGate.resolve(
                suggestion(category = LocalAiDomainCategory.OTHER),
                emptySet(),
                emptySet()
            )
        )
    }

    @Test
    fun modelAllowDoesNotCreatePermanentAllowRule() {
        assertEquals(
            LocalAiPolicyOutcome.NO_AI_RULE,
            LocalAiPolicyGate.resolve(
                suggestion(action = LocalAiSuggestedAction.ALLOW),
                emptySet(),
                emptySet()
            )
        )
    }

    @Test
    fun malformedDomainIsNeverAutoBlocked() {
        assertEquals(
            LocalAiPolicyOutcome.OBSERVE_ONLY,
            LocalAiPolicyGate.resolve(suggestion(domain = "bad domain"), emptySet(), emptySet())
        )
    }
}
