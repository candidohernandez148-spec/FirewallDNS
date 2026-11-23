package com.firewalldns.engine.core

import java.util.concurrent.atomic.AtomicReference

/**
 * In-memory policy evaluator. Rule replacement is atomic; evaluations read an
 * immutable domain index and perform no disk/network I/O or lock acquisition.
 */
class PolicyEngine(initialRules: Collection<PolicyRule> = emptyList()) {
    private data class CompiledRule(
        val rule: PolicyRule,
        val normalizedDomain: String,
    )

    private data class RuleIndex(
        val exactByDomain: Map<String, List<CompiledRule>>,
        val subdomainsByDomain: Map<String, List<CompiledRule>>,
    )

    private data class Snapshot(
        val revision: Long,
        val index: RuleIndex,
    )

    private val snapshot = AtomicReference(Snapshot(0, compile(initialRules)))

    /** Monotonically advances after each successfully published ruleset. */
    val revision: Long
        get() = snapshot.get().revision

    /** Invalid updates are rejected as a whole; the active snapshot is retained. */
    fun replaceRules(newRules: Collection<PolicyRule>) {
        val compiled = compile(newRules)
        snapshot.updateAndGet { current -> Snapshot(current.revision + 1, compiled) }
    }

    /** The explicit time parameter makes expiry behavior deterministic in tests. */
    fun evaluate(
        request: PolicyRequest,
        nowEpochMillis: Long = System.currentTimeMillis(),
    ): PolicyDecision {
        val current = snapshot.get()
        val domain = DomainNormalizer.normalize(request.domain)
            ?: return PolicyDecision(
                action = PolicyAction.ALLOW,
                reason = "invalid_domain_input",
                policyRevision = current.revision,
            )

        var winner: CompiledRule? = null

        fun consider(candidates: List<CompiledRule>?) {
            candidates?.forEach { candidate ->
                val rule = candidate.rule
                if (rule.expiresAtEpochMillis?.let { it <= nowEpochMillis } == true) return@forEach
                if (rule.appPackage != null && rule.appPackage != request.appPackage) return@forEach
                val previous = winner
                if (previous == null || outranks(candidate, previous)) {
                    winner = candidate
                }
            }
        }

        // Exact rules are indexed only at their own host. Suffix rules are
        // checked along the DNS label chain, avoiding a scan of every blocklist
        // entry on each cache miss.
        consider(current.index.exactByDomain[domain])
        var suffix = domain
        while (true) {
            consider(current.index.subdomainsByDomain[suffix])
            val dot = suffix.indexOf('.')
            if (dot < 0) break
            suffix = suffix.substring(dot + 1)
        }

        return winner?.let {
            PolicyDecision(
                action = it.rule.action,
                reason = it.rule.reason,
                ruleId = it.rule.id,
                source = it.rule.source,
                policyRevision = current.revision,
                expiresAtEpochMillis = it.rule.expiresAtEpochMillis,
            )
        } ?: PolicyDecision(
            action = PolicyAction.ALLOW,
            reason = "no_matching_rule",
            policyRevision = current.revision,
        )
    }

    /**
     * Retains the original global ordering: priority, source precedence, domain
     * specificity, exact-before-subdomain, app scope, then stable rule ID.
     */
    private fun outranks(candidate: CompiledRule, current: CompiledRule): Boolean {
        val left = candidate.rule
        val right = current.rule
        if (left.priority != right.priority) return left.priority > right.priority
        if (left.source.precedence != right.source.precedence) {
            return left.source.precedence > right.source.precedence
        }
        if (candidate.normalizedDomain.length != current.normalizedDomain.length) {
            return candidate.normalizedDomain.length > current.normalizedDomain.length
        }
        if (left.includeSubdomains != right.includeSubdomains) return !left.includeSubdomains
        if ((left.appPackage != null) != (right.appPackage != null)) return left.appPackage != null
        return left.id < right.id
    }

    private fun compile(input: Collection<PolicyRule>): RuleIndex {
        val ids = HashSet<String>(input.size)
        val exact = HashMap<String, MutableList<CompiledRule>>()
        val subdomains = HashMap<String, MutableList<CompiledRule>>()

        input.forEach { rule ->
            require(ids.add(rule.id)) { "Policy rule IDs must be unique" }
            require(rule.id.isNotBlank()) { "Policy rule ID must not be blank" }
            require(rule.reason.isNotBlank()) { "Policy rule reason must not be blank" }
            require(rule.source != RuleSource.HEURISTIC || rule.action != PolicyAction.BLOCK) {
                "Heuristic policy rules must never block"
            }
            require(rule.priority in MIN_PRIORITY..MAX_PRIORITY) {
                "Policy rule priority must be between ${MIN_PRIORITY} and ${MAX_PRIORITY}"
            }
            val normalizedDomain = requireNotNull(DomainNormalizer.normalize(rule.domain)) {
                "Invalid domain in policy rule '${rule.id}'"
            }
            rule.appPackage?.let { packageName ->
                require(APP_PACKAGE_PATTERN.matches(packageName)) {
                    "Invalid Android package name in policy rule '${rule.id}'"
                }
            }

            if (rule.enabled) {
                val compiled = CompiledRule(rule, normalizedDomain)
                val index = if (rule.includeSubdomains) subdomains else exact
                index.getOrPut(normalizedDomain) { ArrayList() }.add(compiled)
            }
        }

        return RuleIndex(
            exactByDomain = exact.mapValues { (_, rules) -> rules.toList() },
            subdomainsByDomain = subdomains.mapValues { (_, rules) -> rules.toList() },
        )
    }

    private companion object {
        const val MIN_PRIORITY = -100_000
        const val MAX_PRIORITY = 100_000
        val APP_PACKAGE_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+")
    }
}
