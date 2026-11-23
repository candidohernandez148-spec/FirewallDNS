package com.firewall.dns.domain.ai

/**
 * Safety gate for future on-device model recommendations.
 *
 * This is not an inference engine and does not change network policy by itself.
 * A coordinator may consume its result only after a real local model has produced
 * a structured recommendation. Manual user rules always take precedence.
 */
enum class LocalAiDomainCategory {
    ADVERTISING,
    TRACKER,
    OTHER
}

enum class LocalAiSuggestedAction {
    BLOCK,
    OBSERVE,
    ALLOW
}

enum class LocalAiPolicyOutcome {
    MANUAL_ALLOW,
    MANUAL_BLOCK,
    APPLY_AI_BLOCK,
    OBSERVE_ONLY,
    NO_AI_RULE
}

data class LocalAiDomainSuggestion(
    val domain: String,
    val category: LocalAiDomainCategory,
    val action: LocalAiSuggestedAction,
    val confidence: Float,
    val explanation: String = ""
)

object LocalAiPolicyGate {
    const val DEFAULT_BLOCK_CONFIDENCE = 0.92f

    /**
     * Resolves a model suggestion without mutating any rules.
     * Manual ALLOW/BLOCK entries are supplied from the user's persistent rules.
     * AI is deliberately restricted to high-confidence ad/tracker blocking.
     */
    fun resolve(
        suggestion: LocalAiDomainSuggestion,
        manualAllowed: Set<String>,
        manualBlocked: Set<String>,
        blockConfidence: Float = DEFAULT_BLOCK_CONFIDENCE
    ): LocalAiPolicyOutcome {
        val domain = normalizeDomain(suggestion.domain) ?: return LocalAiPolicyOutcome.OBSERVE_ONLY
        val allowed = manualAllowed.mapNotNull(::normalizeDomain).toSet()
        val blocked = manualBlocked.mapNotNull(::normalizeDomain).toSet()

        if (matches(domain, allowed)) return LocalAiPolicyOutcome.MANUAL_ALLOW
        if (matches(domain, blocked)) return LocalAiPolicyOutcome.MANUAL_BLOCK

        val confidence = suggestion.confidence.takeIf { it.isFinite() } ?: 0f
        if (suggestion.action == LocalAiSuggestedAction.BLOCK &&
            suggestion.category in setOf(
                LocalAiDomainCategory.ADVERTISING,
                LocalAiDomainCategory.TRACKER
            ) &&
            confidence >= blockConfidence.coerceIn(0f, 1f)
        ) {
            return LocalAiPolicyOutcome.APPLY_AI_BLOCK
        }

        return when (suggestion.action) {
            LocalAiSuggestedAction.OBSERVE,
            LocalAiSuggestedAction.BLOCK -> LocalAiPolicyOutcome.OBSERVE_ONLY
            LocalAiSuggestedAction.ALLOW -> LocalAiPolicyOutcome.NO_AI_RULE
        }
    }

    fun normalizeDomain(value: String): String? {
        val clean = value.trim().trim('.').lowercase()
        if (clean.isBlank() || clean.length > 253 || clean.any { it.isWhitespace() }) return null
        if (clean.split('.').any { label ->
                label.isBlank() || label.length > 63 ||
                    label.startsWith('-') || label.endsWith('-') ||
                    label.any { !(it in 'a'..'z' || it in '0'..'9' || it == '-') }
            }
        ) return null
        return clean
    }

    private fun matches(domain: String, rules: Set<String>): Boolean =
        rules.any { rule -> domain == rule || domain.endsWith(".$rule") }
}
