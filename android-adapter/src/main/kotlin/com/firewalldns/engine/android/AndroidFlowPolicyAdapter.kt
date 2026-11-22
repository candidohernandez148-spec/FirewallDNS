package com.firewalldns.engine.android

import com.firewalldns.engine.core.FlowProtocol
import com.firewalldns.engine.core.NetworkFlowDecision
import com.firewalldns.engine.core.NetworkFlowRequest
import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.RuleSource
import com.firewalldns.engine.monitor.FlowIdentity
import com.firewalldns.engine.runtime.EngineRuntime
import java.util.concurrent.ConcurrentHashMap

/**
 * Adapts the packet-stack's flow callbacks to FirewallDNS' single policy and
 * telemetry authorities. UID -1 from Firestack is kept as unknown; it is never
 * guessed from an address or process name.
 */
class AndroidFlowPolicyAdapter(
    private val engine: EngineRuntime,
    private val resolvePackage: (Int) -> String? = { null },
    private val networkGeneration: () -> Long = { 0L },
    private val isUidBlocked: (Int) -> Boolean = { false },
    private val nowEpochMillis: () -> Long = System::currentTimeMillis,
) {
    private val packageCache = ConcurrentHashMap<Int, String>()

    fun resolvePackageForUid(uid: Int): String? {
        if (uid < 0) return null
        if (packageCache.size > 4096) packageCache.clear()
        return packageCache.computeIfAbsent(uid) { runCatching { resolvePackage(it) }.getOrNull().orEmpty() }
            .takeIf(String::isNotEmpty)
    }
    fun evaluate(
        flowId: String,
        protocolNumber: Int,
        ownerUid: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
        domainDecision: NetworkFlowDecision? = null,
        destinationAddresses: List<String> = listOf(destinationAddress),
    ): NetworkFlowDecision {
        require(flowId.isNotBlank())
        val protocol = when (protocolNumber) {
            6 -> FlowProtocol.TCP
            17 -> FlowProtocol.UDP
            1, 58 -> FlowProtocol.ICMP
            else -> return NetworkFlowDecision(
                action = com.firewalldns.engine.core.PolicyAction.ALLOW,
                reason = "unsupported_flow_protocol",
                policyRevision = engine.flowPolicyRevision,
            )
        }
        val uid = ownerUid.takeIf { it >= 0 }
        val appPackage = uid?.let(::resolvePackageForUid)
        val request = NetworkFlowRequest(
            protocol = protocol,
            appUid = uid,
            appPackage = appPackage,
            destinationAddress = destinationAddress,
            destinationPort = destinationPort,
        )
        val evaluatedDestinations = destinationAddresses.distinct().mapNotNull { candidate ->
            runCatching {
                candidate to engine.evaluateFlow(request.copy(destinationAddress = candidate), nowEpochMillis())
            }.getOrNull()
        }.ifEmpty {
            listOf(destinationAddress to engine.evaluateFlow(request, nowEpochMillis()))
        }
        // Firestack may expose a synthetic ALG destination plus one or more
        // original IPs. Apply CIDR rules to every original target and prefer
        // the strongest applicable decision for the connection.
        val selectedDestination = evaluatedDestinations.firstOrNull { it.second.action == PolicyAction.BLOCK }
            ?: evaluatedDestinations.firstOrNull { it.second.action == PolicyAction.OBSERVE }
            ?: evaluatedDestinations.first()
        val flowDecision = selectedDestination.second
        val appBlocked = uid != null && runCatching { isUidBlocked(uid) }.getOrDefault(false)
        val decision = when {
            appBlocked -> NetworkFlowDecision(
                action = PolicyAction.BLOCK,
                reason = "app_uid_blocked",
                ruleId = "app-uid-$uid",
                source = RuleSource.USER,
                policyRevision = engine.flowPolicyRevision,
            )
            flowDecision.action == PolicyAction.BLOCK -> flowDecision
            domainDecision?.action == PolicyAction.BLOCK -> domainDecision
            domainDecision?.action == PolicyAction.OBSERVE -> domainDecision
            else -> flowDecision
        }
        engine.flowMonitor.open(
            FlowIdentity(
                id = flowId,
                protocol = protocol,
                appUid = uid,
                appPackage = appPackage,
                sourceAddress = sourceAddress,
                sourcePort = sourcePort,
                destinationAddress = selectedDestination.first,
                destinationPort = destinationPort,
                networkGeneration = networkGeneration(),
            ),
            decision,
            nowEpochMillis(),
        )
        return decision
    }

    fun recordBytes(flowId: String, sent: Long, received: Long): Boolean =
        engine.flowMonitor.recordBytes(flowId, sent, received, nowEpochMillis())

    fun close(flowId: String): Boolean = engine.flowMonitor.close(flowId)
}
