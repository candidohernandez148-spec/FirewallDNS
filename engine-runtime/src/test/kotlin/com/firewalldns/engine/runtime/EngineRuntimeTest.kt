package com.firewalldns.engine.runtime

import com.firewalldns.engine.core.FlowProtocol
import com.firewalldns.engine.core.NetworkFlowRequest
import com.firewalldns.engine.core.NetworkFlowRule
import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.core.RuleSource
import com.firewalldns.engine.dns.DnsEvaluation
import com.firewalldns.engine.monitor.EngineEventType
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class EngineRuntimeTest {
    @Test fun oneRuntimeAppliesUserPolicyAndPublishesMonitorEvents() {
        val runtime = EngineRuntime(
            initialRules = listOf(
                PolicyRule(
                    id = "block-bad",
                    domain = "bad.example",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.USER,
                    reason = "user_block_rule",
                ),
            ),
        )

        val result = runtime.evaluateDns(query("bad.example"), appPackage = "com.example.app", nowEpochMillis = 100)

        val blocked = assertIs<DnsEvaluation.Blocked>(result)
        assertEquals("bad.example", blocked.question.domain)
        assertEquals(PolicyAction.BLOCK, blocked.decision.action)
        assertEquals(1L, runtime.metrics().blocked)
        assertEquals(EngineEventType.DNS_BLOCKED, runtime.drainEvents(1).single().type)
    }

    @Test fun observeDecisionForwardsInsteadOfBlocking() {
        val runtime = EngineRuntime(
            initialRules = listOf(
                PolicyRule(
                    id = "observe-analytics",
                    domain = "analytics.example",
                    action = PolicyAction.OBSERVE,
                    source = RuleSource.MANAGED,
                    reason = "tracking_observed",
                ),
            ),
        )

        val result = runtime.evaluateDns(query("analytics.example"), nowEpochMillis = 100)

        val forward = assertIs<DnsEvaluation.Forward>(result)
        assertEquals(PolicyAction.OBSERVE, forward.decision.action)
        assertEquals(1L, runtime.metrics().observed)
    }

    @Test fun replacingRulesAdvancesRevisionAndChangesDecision() {
        val runtime = EngineRuntime()
        val initialRevision = runtime.policyRevision
        runtime.replaceRules(
            listOf(
                PolicyRule(
                    id = "allow-domain",
                    domain = "example.com",
                    action = PolicyAction.ALLOW,
                    source = RuleSource.USER,
                    reason = "explicit_allow",
                ),
            ),
        )

        assertEquals(initialRevision + 1, runtime.policyRevision)
        val result = assertIs<DnsEvaluation.Forward>(
            runtime.evaluateDns(query("example.com"), nowEpochMillis = 100),
        )
        assertEquals("explicit_allow", result.decision.reason)
    }

    @Test fun domainCallbackUsesSameCuratedThreatKnowledge() {
        val runtime = EngineRuntime()
        val blocked = runtime.evaluateDomain("ads.doubleclick.net", "com.example.app", 100)
        assertEquals(PolicyAction.BLOCK, blocked.action)
        assertEquals("known_ad_delivery_domain", blocked.reason)

        val observed = runtime.evaluateDomain("metrics.example.net", "com.example.app", 101)
        assertEquals(PolicyAction.OBSERVE, observed.action)
        assertEquals("heuristic_signals_require_observation", observed.reason)
        assertEquals(2L, runtime.metrics().decisions)
    }

    @Test fun runtimeExposesNetworkFlowPolicyForTheTunAdapter() {
        val runtime = EngineRuntime()
        runtime.replaceFlowRules(
            listOf(
                NetworkFlowRule(
                    id = "block-app-https",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.USER,
                    reason = "app_network_rule",
                    protocol = FlowProtocol.TCP,
                    appUid = 10234,
                    destinationPort = 443,
                ),
            ),
        )

        val result = runtime.evaluateFlow(
            NetworkFlowRequest(FlowProtocol.TCP, 10234, "com.example.app", "198.51.100.20", 443),
            nowEpochMillis = 100,
        )

        assertEquals(PolicyAction.BLOCK, result.action)
        assertEquals("block-app-https", result.ruleId)
        assertEquals(1L, runtime.flowPolicyRevision)
    }

    private fun query(domain: String): ByteArray {
        val name = domain.split('.').flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray(Charsets.US_ASCII).toList()
        } + 0.toByte()
        val question = name.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            it[0] = 0x12
            it[1] = 0x34
            it[2] = 0x01
            it[5] = 1
            question.copyInto(it, 12)
        }
    }
}
