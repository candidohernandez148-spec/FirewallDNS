package com.firewall.dns.domain.engine

object RuleEvaluator {

    data class AdblockParseResult(
        val domain: String,
        val isException: Boolean
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
            .substringBefore('$')
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
     * deliberately rejected rather than silently widened into global domain blocks.
     */
    fun parseAdblockLine(raw: String): AdblockParseResult? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("!") || trimmed.startsWith("#")) return null

        val noComment = trimmed.substringBefore("#").trim()
        if (noComment.isEmpty()) return null

        val isException = noComment.startsWith("@@")
        val body = if (isException) noComment.removePrefix("@@") else noComment

        // A DNS policy cannot enforce URL-, app-, client-, or record-type-specific
        // Adblock options. Accept only $important, whose meaning remains global.
        fun hasOnlyDnsSafeOptions(value: String): Boolean {
            val marker = value.indexOf('$')
            if (marker < 0) return true
            val options = value.substring(marker + 1).split(',')
            return options.isNotEmpty() && options.all { it.trim().equals("important", ignoreCase = true) }
        }

        val candidate = when {
            body.startsWith("||") -> {
                if (!hasOnlyDnsSafeOptions(body)) return null
                val rawTarget = body.removePrefix("||")
                    .substringBefore('$')
                    .removeSuffix("^")
                if (rawTarget.isEmpty() || rawTarget.contains('/') || rawTarget.contains('*') ||
                    rawTarget.contains('^') || rawTarget.contains(':')
                ) return null
                rawTarget
            }
            body.startsWith("0.0.0.0") || body.startsWith("127.0.0.1") || body.startsWith("::") -> {
                val parts = body.split(Regex("\\s+")).filter(String::isNotBlank)
                if (parts.size < 2) return null
                parts[1]
            }
            else -> {
                if (!hasOnlyDnsSafeOptions(body)) return null
                val rawTarget = body.substringBefore('$').removeSuffix("^")
                if (rawTarget.isEmpty() || rawTarget.contains('/') || rawTarget.contains('*') ||
                    rawTarget.contains('^') || rawTarget.contains(':')
                ) return null
                rawTarget
            }
        }

        val domain = canonicalizeDomain(candidate) ?: return null
        return AdblockParseResult(domain = domain, isException = isException)
    }

    fun normalizeManualDomain(raw: String): String? = canonicalizeDomain(
        raw.trim()
            .removePrefix("@@")
            .removePrefix("||")
            .removePrefix("*.")
            .substringBefore('^')
            .substringBefore('$')
    )

    fun evaluate(
        domain: String,
        customAllow: Set<String>,
        customBlock: Set<String>,
        hostExceptions: Set<String>,
        hostBlock: Set<String>
    ): Pair<Boolean, String> {
        val decision = evaluateDecision(domain, customAllow, customBlock, hostExceptions, hostBlock)
        return decision.blocked to decision.reason
    }

    fun evaluateDecision(
        domain: String,
        customAllow: Set<String>,
        customBlock: Set<String>,
        hostExceptions: Set<String>,
        hostBlock: Set<String>
    ): DecisionResult {
        val clean = domain.trim().trimEnd('.').lowercase()

        if (matchesDomainOrParent(clean, customAllow)) {
            return DecisionResult(false, "Lista blanca", RuleSource.MANUAL_ALLOW)
        }
        if (matchesDomainOrParent(clean, customBlock)) {
            return DecisionResult(true, "Regla propia", RuleSource.MANUAL_BLOCK)
        }
        if (matchesDomainOrParent(clean, hostExceptions)) {
            return DecisionResult(false, "Excepción @@||", RuleSource.LIST_EXCEPTION)
        }
        if (matchesDomainOrParent(clean, hostBlock)) {
            return DecisionResult(true, "Adblock ||^", RuleSource.LIST_BLOCK)
        }
        return DecisionResult(false, "Permitido", RuleSource.CACHE, cacheTtlMs = 30_000L)
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
