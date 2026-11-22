package com.firewalldns.engine.runtime

import com.firewalldns.engine.core.NetworkFlowDecision
import com.firewalldns.engine.core.NetworkFlowPolicyEngine
import com.firewalldns.engine.core.NetworkFlowRequest
import com.firewalldns.engine.core.NetworkFlowRule
import com.firewalldns.engine.core.PolicyDecision
import com.firewalldns.engine.core.PolicyEngine
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.dns.DnsEvaluation
import com.firewalldns.engine.dns.DnsPolicyAdapter
import com.firewalldns.engine.monitor.EngineEvent
import com.firewalldns.engine.monitor.EngineMetricsSnapshot
import com.firewalldns.engine.monitor.FlowConnectionMonitor
import com.firewalldns.engine.monitor.EngineMonitor
import com.firewalldns.engine.threat.ThreatAnalyzer

/**
 * Single public entry point for the FirewallDNS decision engine.
 *
 * Android owns the VPN/TUN lifecycle and supplies validated DNS packets plus
 * app identity. This runtime owns all policy, threat, DNS decision and monitor
 * behavior. It deliberately performs no persistence or socket I/O here.
 */
class EngineRuntime(
    initialRules: Collection<PolicyRule> = emptyList(),
    private val threatAnalyzer: ThreatAnalyzer = ThreatAnalyzer(),
    val monitor: EngineMonitor = EngineMonitor(),
    val flowMonitor: FlowConnectionMonitor = FlowConnectionMonitor(),
) {
    private val policyEngine = PolicyEngine(initialRules)
    private val networkFlowPolicy = NetworkFlowPolicyEngine()
    private val dnsAdapter = DnsPolicyAdapter(
        policyEngine = policyEngine,
        threatAnalyzer = threatAnalyzer,
        monitor = monitor,
    )

    val policyRevision: Long
        get() = policyEngine.revision

    val flowPolicyRevision: Long
        get() = networkFlowPolicy.revision

    /** Atomically replaces the complete rules snapshot. */
    fun replaceRules(rules: Collection<PolicyRule>) {
        policyEngine.replaceRules(rules)
    }

    /** Atomically replaces TCP/UDP/ICMP flow rules used by the TUN stack adapter. */
    fun replaceFlowRules(rules: Collection<NetworkFlowRule>) {
        networkFlowPolicy.replaceRules(rules)
    }

    /** Evaluates a validated network flow without disk or socket I/O. */
    fun evaluateFlow(
        request: NetworkFlowRequest,
        nowEpochMillis: Long = System.currentTimeMillis(),
    ): NetworkFlowDecision = networkFlowPolicy.evaluate(request, nowEpochMillis)

    /** Domain-level DNS decision for packet stacks that expose decoded questions. */
    fun evaluateDomain(
        domain: String,
        appPackage: String? = null,
        nowEpochMillis: Long = System.currentTimeMillis(),
    ): PolicyDecision = dnsAdapter.evaluateDomain(domain, appPackage, nowEpochMillis)

    /** Evaluates one DNS packet; OBSERVE always forwards and BLOCK synthesizes NXDOMAIN. */
    fun evaluateDns(
        packet: ByteArray,
        appPackage: String? = null,
        nowEpochMillis: Long = System.currentTimeMillis(),
    ): DnsEvaluation = dnsAdapter.evaluate(packet, appPackage, nowEpochMillis)

    /** Drains a bounded number of local monitor events for the host UI/storage adapter. */
    fun drainEvents(maxCount: Int): List<EngineEvent> = monitor.drainEvents(maxCount)

    fun metrics(): EngineMetricsSnapshot = monitor.snapshot()

    /** Expires stale flow telemetry without blocking the packet-processing path. */
    fun evictIdleFlows(nowEpochMillis: Long = System.currentTimeMillis()): Int =
        flowMonitor.evictIdle(nowEpochMillis)
}
