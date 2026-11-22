package com.firewalldns.engine.core

import java.net.InetAddress
import java.util.concurrent.atomic.AtomicReference

enum class FlowProtocol { TCP, UDP, ICMP }

data class NetworkFlowRule(
    val id: String,
    val action: PolicyAction,
    val source: RuleSource,
    val reason: String,
    val protocol: FlowProtocol? = null,
    val appUid: Int? = null,
    val appPackage: String? = null,
    val destinationCidr: String? = null,
    val destinationPort: Int? = null,
    val priority: Int = 0,
    val enabled: Boolean = true,
    val expiresAtEpochMillis: Long? = null,
)

data class NetworkFlowRequest(
    val protocol: FlowProtocol,
    val appUid: Int?,
    val appPackage: String?,
    val destinationAddress: String,
    val destinationPort: Int,
) {
    init {
        require(appUid == null || appUid >= 0) { "UID must be non-negative or unknown" }
        require(destinationPort in 1..65535) { "Destination port must be between 1 and 65535" }
        require(parseIp(destinationAddress) != null) { "Destination address must be a numeric IPv4 or IPv6 address" }
    }
}

data class NetworkFlowDecision(
    val action: PolicyAction,
    val reason: String,
    val ruleId: String? = null,
    val source: RuleSource? = null,
    val policyRevision: Long = 0,
)

private data class CompiledFlowRule(
    val rule: NetworkFlowRule,
    val network: ByteArray?,
    val prefixBits: Int,
) {
    fun matches(request: NetworkFlowRequest, destination: ByteArray): Boolean {
        val r = rule
        if (r.protocol != null && r.protocol != request.protocol) return false
        if (r.appUid != null && r.appUid != request.appUid) return false
        if (r.appPackage != null && r.appPackage != request.appPackage) return false
        if (r.destinationPort != null && r.destinationPort != request.destinationPort) return false
        val expected = network ?: return true
        if (expected.size != destination.size) return false
        val wholeBytes = prefixBits / 8
        val remainingBits = prefixBits % 8
        for (i in 0 until wholeBytes) if (expected[i] != destination[i]) return false
        if (remainingBits != 0) {
            val mask = (0xff shl (8 - remainingBits)) and 0xff
            if ((expected[wholeBytes].toInt() and mask) != (destination[wholeBytes].toInt() and mask)) return false
        }
        return true
    }
}

/**
 * Lock-free read path for TCP/UDP/ICMP flow decisions.
 * Rules are compiled before atomic publication; evaluation performs no I/O.
 */
class NetworkFlowPolicyEngine(initialRules: Collection<NetworkFlowRule> = emptyList()) {
    private data class Snapshot(val revision: Long, val rules: List<CompiledFlowRule>)
    private val snapshot = AtomicReference(Snapshot(0, compile(initialRules)))

    val revision: Long get() = snapshot.get().revision

    fun replaceRules(rules: Collection<NetworkFlowRule>) {
        val compiled = compile(rules)
        snapshot.updateAndGet { current -> Snapshot(current.revision + 1, compiled) }
    }

    fun evaluate(request: NetworkFlowRequest, nowEpochMillis: Long = System.currentTimeMillis()): NetworkFlowDecision {
        val current = snapshot.get()
        val destination = requireNotNull(parseIp(request.destinationAddress))
        val winner = current.rules.firstOrNull { compiled ->
            compiled.rule.enabled &&
                (compiled.rule.expiresAtEpochMillis?.let { it > nowEpochMillis } ?: true) &&
                compiled.matches(request, destination)
        }
        return winner?.let {
            NetworkFlowDecision(it.rule.action, it.rule.reason, it.rule.id, it.rule.source, current.revision)
        } ?: NetworkFlowDecision(PolicyAction.ALLOW, "no_matching_flow_rule", policyRevision = current.revision)
    }

    private fun compile(input: Collection<NetworkFlowRule>): List<CompiledFlowRule> {
        require(input.map { it.id }.distinct().size == input.size) { "Flow rule IDs must be unique" }
        return input.map { rule ->
            require(rule.id.isNotBlank()) { "Flow rule ID must not be blank" }
            require(rule.reason.isNotBlank()) { "Flow rule reason must not be blank" }
            require(rule.source != RuleSource.HEURISTIC || rule.action != PolicyAction.BLOCK) {
                "Heuristic flow rules must never block"
            }
            require(rule.priority in -100_000..100_000) { "Flow rule priority is out of range" }
            require(rule.appUid == null || rule.appUid >= 0) { "Flow rule UID must be non-negative" }
            rule.appPackage?.let {
                require(Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+").matches(it)) {
                    "Invalid Android package name in flow rule '${rule.id}'"
                }
            }
            rule.destinationPort?.let { require(it in 1..65535) { "Invalid destination port in flow rule '${rule.id}'" } }
            require(
                rule.protocol != null || rule.appUid != null || rule.appPackage != null ||
                    rule.destinationCidr != null || rule.destinationPort != null
            ) { "Flow rule '${rule.id}' must contain at least one selector" }

            val parsed = rule.destinationCidr?.let(::parseCidr)
            CompiledFlowRule(rule, parsed?.first, parsed?.second ?: 0)
        }.sortedWith(
            compareByDescending<CompiledFlowRule> { it.rule.priority }
                .thenByDescending { it.rule.source.precedence }
                .thenByDescending { it.prefixBits }
                .thenByDescending { it.rule.appUid != null }
                .thenByDescending { it.rule.appPackage != null }
                .thenByDescending { it.rule.destinationPort != null }
                .thenByDescending { it.rule.protocol != null }
                .thenBy { it.rule.id },
        )
    }

    private companion object {
        fun parseCidr(value: String): Pair<ByteArray, Int> {
            val parts = value.split('/')
            require(parts.size == 2) { "Invalid CIDR '$value'" }
            val address = requireNotNull(parseIp(parts[0])) { "Invalid IP in CIDR '$value'" }
            val bits = parts[1].toIntOrNull()
                ?: throw IllegalArgumentException("Invalid prefix in CIDR '$value'")
            require(bits in 0..address.size * 8) { "CIDR prefix out of range in '$value'" }
            val network = address.copyOf()
            val wholeBytes = bits / 8
            val remainingBits = bits % 8
            if (remainingBits != 0) {
                network[wholeBytes] = (network[wholeBytes].toInt() and ((0xff shl (8 - remainingBits)) and 0xff)).toByte()
            }
            for (i in (wholeBytes + if (remainingBits == 0) 0 else 1) until network.size) network[i] = 0
            return network to bits
        }

        fun parseIp(value: String): ByteArray? {
            val unscoped = value.substringBefore('%')
            val validLiteral = if (unscoped.contains(':')) {
                Regex("[0-9A-Fa-f:.]+").matches(unscoped)
            } else {
                Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}").matches(unscoped) &&
                    unscoped.split('.').all { part -> part.toIntOrNull()?.let { it in 0..255 } == true }
            }
            if (!validLiteral) return null
            return runCatching { InetAddress.getByName(unscoped).address }.getOrNull()
                ?.takeIf { it.size == 4 || it.size == 16 }
        }
    }
}
