package com.firewalldns.engine.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class NetworkFlowPolicyEngineTest {
    @Test fun blocksMatchingUidProtocolPortAndIpv4Range() {
        val engine = NetworkFlowPolicyEngine(
            listOf(
                NetworkFlowRule(
                    id = "block-app-tcp",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.USER,
                    reason = "user_flow_rule",
                    protocol = FlowProtocol.TCP,
                    appUid = 10234,
                    destinationCidr = "203.0.113.0/24",
                    destinationPort = 443,
                ),
            ),
        )

        val result = engine.evaluate(
            NetworkFlowRequest(
                protocol = FlowProtocol.TCP,
                appUid = 10234,
                appPackage = "com.example.app",
                destinationAddress = "203.0.113.88",
                destinationPort = 443,
            ),
            nowEpochMillis = 100,
        )

        assertEquals(PolicyAction.BLOCK, result.action)
        assertEquals("block-app-tcp", result.ruleId)
        assertEquals("user_flow_rule", result.reason)
    }

    @Test fun unknownUidDoesNotMatchAnAppSpecificRule() {
        val engine = NetworkFlowPolicyEngine(
            listOf(
                NetworkFlowRule(
                    id = "block-known-app",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.USER,
                    reason = "known_uid_only",
                    appUid = 10234,
                ),
            ),
        )

        val result = engine.evaluate(
            NetworkFlowRequest(FlowProtocol.UDP, null, null, "198.51.100.10", 443),
        )

        assertEquals(PolicyAction.ALLOW, result.action)
        assertEquals("no_matching_flow_rule", result.reason)
    }

    @Test fun matchesIpv6PrefixAndHonorsExpiry() {
        val engine = NetworkFlowPolicyEngine(
            listOf(
                NetworkFlowRule(
                    id = "expired-ipv6",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.USER,
                    reason = "expired",
                    destinationCidr = "2001:db8:abcd::/48",
                    expiresAtEpochMillis = 99,
                ),
                NetworkFlowRule(
                    id = "block-ipv6",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.MANAGED,
                    reason = "managed_ipv6_range",
                    protocol = FlowProtocol.UDP,
                    destinationCidr = "2001:db8:abcd::/48",
                ),
            ),
        )

        val result = engine.evaluate(
            NetworkFlowRequest(FlowProtocol.UDP, 10001, "com.example.app", "2001:db8:abcd:1::10", 5353),
            nowEpochMillis = 100,
        )

        assertEquals(PolicyAction.BLOCK, result.action)
        assertEquals("block-ipv6", result.ruleId)
    }

    @Test fun heuristicRulesCannotBlockAndInvalidReplacementIsAtomic() {
        val engine = NetworkFlowPolicyEngine()
        assertFailsWith<IllegalArgumentException> {
            engine.replaceRules(
                listOf(
                    NetworkFlowRule(
                        id = "heuristic-block",
                        action = PolicyAction.BLOCK,
                        source = RuleSource.HEURISTIC,
                        reason = "insufficient_confidence",
                        protocol = FlowProtocol.TCP,
                    ),
                ),
            )
        }
        assertEquals(0L, engine.revision)
        assertEquals(
            PolicyAction.ALLOW,
            engine.evaluate(NetworkFlowRequest(FlowProtocol.TCP, null, null, "192.0.2.1", 443)).action,
        )
    }
}
