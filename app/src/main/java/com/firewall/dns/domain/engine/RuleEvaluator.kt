package com.firewall.dns.domain.engine

object RuleEvaluator {

    data class AdblockParseResult(
        val domain: String,
        val isException: Boolean,
        val isImportant: Boolean = false
    )

    fun canonicalizeDomain(raw: String): String? {
        val cleaned = raw.trim().lowercase()
            .removePrefix("@@")
            .removePrefix("||")
            .removePrefix("*.")
            .removePrefix("https://")
            .removePrefix("http://")
            .removePrefix("ftp://")
            .substringBefore('^')
            .substringBefore(36.toChar())
            .substringBefore('?')
            .substringBefore('/')
            .substringBeforeLast(':')
            .trim()
            .trimEnd('.')

        if (cleaned.isEmpty() || cleaned.startsWith('.')) return null
        if (cleaned.any { it.isWhitespace() }) return null
        if (!cleaned.contains('.')) return null

        val labels = cleaned.split('.')
        if (labels.any { label ->
                label.isEmpty() || label.length > 63 ||
                    label.first() == '-' || label.last() == '-' ||
                    label.any { char -> !(char in 'a'..'z' || char in '0'..'9' || char == '-') }
            }
        ) return null

        return cleaned
    }

    /**
     * Parses only rules whose semantics can be enforced by a DNS-only policy.
     * URL-, resource-, client-, and request-context-dependent options are
     * rejected rather than silently widened into global domain blocks.
     */
    fun parseAdblockLine(raw: String): AdblockParseResult? =
        parseAdblockLineEntries(raw).firstOrNull()

    /**
     * Returns every DNS host from hosts-format lines. Some feeds put several
     * aliases on one line; retaining only the first silently loses rules.
     */
    fun parseAdblockLineEntries(raw: String): List<AdblockParseResult> {
        val trimmed = raw.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("!") || trimmed.startsWith("#")) return emptyList()

        val noComment = trimmed.substringBefore("#").trim()
        if (noComment.isEmpty()) return emptyList()

        val isException = noComment.startsWith("@@")
        val body = if (isException) noComment.removePrefix("@@") else noComment

        // Only the global important modifier is supported. Other modifiers
        // depend on client, DNS type, CNAME, or rule-disabling semantics.
        fun parseImportantOption(value: String): Boolean? {
            val marker = value.indexOf(36.toChar())
            if (marker < 0) return false
            val options = value.substring(marker + 1).split(',')
            return if (options.isNotEmpty() && options.all {
                    it.trim().equals("important", ignoreCase = true)
                }
            ) true else null
        }

        val tokens = body.split(Regex("\\s+")).filter(String::isNotBlank)
        if (!isException && tokens.size >= 2 && tokens.first() in HOST_SINK_ADDRESSES) {
            if (tokens.any { token -> token.any { it.code == 36 } }) return emptyList()
            return tokens.drop(1).mapNotNull { canonicalizeDomain(it) }
                .distinct()
                .map { AdblockParseResult(domain = it, isException = false) }
        }

        val important = parseImportantOption(body) ?: return emptyList()
        val candidate = when {
            body.startsWith("||") -> {
                val rawTarget = body.removePrefix("||")
                    .substringBefore(36.toChar())
                    .removeSuffix("^")
                if (rawTarget.isEmpty() || rawTarget.contains('/') || rawTarget.contains('*') ||
                    rawTarget.contains('^') || rawTarget.contains(':')
                ) return emptyList()
                rawTarget
            }
            else -> {
                val rawTarget = body.substringBefore(36.toChar()).removeSuffix("^")
                if (rawTarget.isEmpty() || rawTarget.contains('/') || rawTarget.contains('*') ||
                    rawTarget.contains('^') || rawTarget.contains(':')
                ) return emptyList()
                rawTarget
            }
        }

        val domain = canonicalizeDomain(candidate) ?: return emptyList()
        return listOf(
            AdblockParseResult(domain = domain, isException = isException, isImportant = important)
        )
    }

    fun normalizeManualDomain(raw: String): String? = canonicalizeDomain(
        raw.trim()
            .removePrefix("@@")
            .removePrefix("||")
            .removePrefix("*.")
            .substringBefore('^')
            .substringBefore(36.toChar())
    )

    fun evaluate(
        domain: String,
        customAllow: Set<String>,
        customBlock: Set<String>,
        hostExceptions: Set<String>,
        hostBlock: Set<String>,
        importantExceptions: Set<String> = emptySet(),
        importantBlock: Set<String> = emptySet()
    ): Pair<Boolean, String> {
        val decision = evaluateDecision(
            domain, customAllow, customBlock, hostExceptions, hostBlock, importantExceptions, importantBlock
        )
        return decision.blocked to decision.reason
    }

    fun evaluateDecision(
        domain: String,
        customAllow: Set<String>,
        customBlock: Set<String>,
        hostExceptions: Set<String>,
        hostBlock: Set<String>,
        importantExceptions: Set<String> = emptySet(),
        importantBlock: Set<String> = emptySet()
    ): DecisionResult {
        val clean = domain.trim().trimEnd('.').lowercase()

        // Explicit user choices outrank downloaded feeds.
        if (matchesDomainOrParent(clean, customAllow)) {
            return DecisionResult(false, "Lista blanca", RuleSource.MANUAL_ALLOW)
        }
        if (matchesDomainOrParent(clean, customBlock)) {
            return DecisionResult(true, "Regla propia", RuleSource.MANUAL_BLOCK)
        }

        // AdGuard DNS important exceptions override important blocks; important
        // blocks override normal list exceptions and normal list blocks.
        if (matchesDomainOrParent(clean, importantExceptions)) {
            return DecisionResult(false, "Excepción importante @@||", RuleSource.LIST_EXCEPTION)
        }
        if (matchesDomainOrParent(clean, importantBlock)) {
            return DecisionResult(true, "Adblock importante ||^", RuleSource.LIST_BLOCK)
        }
        if (matchesDomainOrParent(clean, hostExceptions)) {
            return DecisionResult(false, "Excepción @@||", RuleSource.LIST_EXCEPTION)
        }
        if (matchesDomainOrParent(clean, hostBlock)) {
            return DecisionResult(true, "Adblock ||^", RuleSource.LIST_BLOCK)
        }
        return DecisionResult(false, "Permitido", RuleSource.CACHE, cacheTtlMs = 30_000L)
    }

    private companion object {
        val HOST_SINK_ADDRESSES = setOf(
            "0.0.0.0",
            "127.0.0.1",
            "::",
            "::1",
            "0:0:0:0:0:0:0:0",
            "0:0:0:0:0:0:0:1"
        )
    }

    private fun matchesDomainOrParent(domain: String, set: Set<String>): Boolean {
        var current = domain
        while (true) {
            if (set.contains(current)) return true
            val dot = current.indexOf('.')
            if (dot == -1) break
            current = current.substring(dot + 1)
        }
        return false
    }
}
