package com.firewalldns.engine.android

import com.firewalldns.engine.core.FlowProtocol
import com.firewalldns.engine.core.NetworkFlowRule
import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.RuleSource
import com.firewalldns.engine.runtime.EngineRuntime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidFlowPolicyAdapterTest {
    @Test fun mapsBlockedDnsToFirestackBlockAllTransportNotFlowBlockProxy() {
        assertEquals("BlockAll", dnsTransportForPolicyAction(PolicyAction.BLOCK))
        assertEquals("Default", dnsTransportForPolicyAction(PolicyAction.OBSERVE))
        assertEquals("Default", dnsTransportForPolicyAction(PolicyAction.ALLOW))
    }

    @Test fun curatedDomainThreatCanBlockTheAssociatedNetworkFlow() {
        val engine = EngineRuntime()
        val domainDecision = engine.evaluateDomain("ads.doubleclick.net", "com.example.app", 100)
        val adapter = AndroidFlowPolicyAdapter(engine, nowEpochMillis = { 101L })
        val decision = adapter.evaluate(
            flowId = "tcp-domain-block",
            protocolNumber = 6,
            ownerUid = -1,
            sourceAddress = "10.10.10.2",
            sourcePort = 42000,
            destinationAddress = "203.0.113.10",
            destinationPort = 443,
            domainDecision = com.firewalldns.engine.core.NetworkFlowDecision(
                domainDecision.action,
                domainDecision.reason,
                domainDecision.ruleId,
                domainDecision.source,
                domainDecision.policyRevision,
            ),
        )
        assertEquals(PolicyAction.BLOCK, decision.action)
        assertEquals(1L, engine.flowMonitor.snapshot().blocked)
    }

    @Test fun resolvesKnownUidAndAppliesAppSpecificBlock() {
        val engine = EngineRuntime()
        engine.replaceFlowRules(
            listOf(
                NetworkFlowRule(
                    id = "block-app-https",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.USER,
                    reason = "app_https_blocked",
                    protocol = FlowProtocol.TCP,
                    appUid = 10234,
                    destinationPort = 443,
                ),
            ),
        )
        val adapter = AndroidFlowPolicyAdapter(
            engine = engine,
            resolvePackage = { uid -> if (uid == 10234) "com.example.app" else null },
            networkGeneration = { 9L },
            nowEpochMillis = { 100L },
        )

        val decision = adapter.evaluate(
            flowId = "tcp-1",
            protocolNumber = 6,
            ownerUid = 10234,
            sourceAddress = "10.10.10.2",
            sourcePort = 42000,
            destinationAddress = "203.0.113.10",
            destinationPort = 443,
        )

        assertEquals(PolicyAction.BLOCK, decision.action)
        assertEquals(1L, engine.flowMonitor.snapshot().blocked)
        assertEquals(0, engine.flowMonitor.snapshot().active)
    }

    @Test fun unknownUidIsNotGuessedAndAllowedFlowIsTracked() {
        val engine = EngineRuntime()
        engine.replaceFlowRules(
            listOf(
                NetworkFlowRule(
                    id = "block-known-app-only",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.USER,
                    reason = "uid_specific",
                    appUid = 10234,
                ),
            ),
        )
        val adapter = AndroidFlowPolicyAdapter(engine, networkGeneration = { 4L }, nowEpochMillis = { 200L })

        val decision = adapter.evaluate(
            "udp-1", 17, -1, "10.10.10.2", 53000, "198.51.100.53", 53,
        )

        assertEquals(PolicyAction.ALLOW, decision.action)
        val active = engine.flowMonitor.snapshot().flows.single()
        assertEquals(null, active.identity.appUid)
        assertEquals(null, active.identity.appPackage)
        assertEquals(4L, active.identity.networkGeneration)
        assertTrue(adapter.recordBytes("udp-1", sent = 80, received = 120))
        assertTrue(adapter.close("udp-1"))
        assertFalse(adapter.close("udp-1"))
    }

    @Test fun appliesExistingPerAppFirewallBlockBeforeFlowRuleFallback() {
        val engine = EngineRuntime()
        val adapter = AndroidFlowPolicyAdapter(
            engine = engine,
            isUidBlocked = { it == 12001 },
            nowEpochMillis = { 300L },
        )
        val decision = adapter.evaluate(
            "tcp-app-block", 6, 12001, "10.10.10.2", 40000, "203.0.113.9", 443,
        )
        assertEquals(PolicyAction.BLOCK, decision.action)
        assertEquals("app_uid_blocked", decision.reason)
        assertEquals(1L, engine.flowMonitor.snapshot().blocked)
    }

    @Test fun mapsIcmpWithoutInventingTransportPorts() {
        val engine = EngineRuntime()
        val adapter = AndroidFlowPolicyAdapter(engine, nowEpochMillis = { 1L })
        val decision = adapter.evaluate(
            "icmp-1", 58, -1, "fd00::2", 0, "2001:db8::1", 0,
        )
        assertEquals(PolicyAction.ALLOW, decision.action)
        val flow = engine.flowMonitor.snapshot().flows.single()
        assertEquals(FlowProtocol.ICMP, flow.identity.protocol)
        assertEquals(0, flow.identity.destinationPort)
    }
    @Test fun parsesIpv4Ipv6AndScopedIpv6FlowEndpoints() {
        assertEquals("192.0.2.10" to 443, parseFirestackEndpoint("192.0.2.10:443", false))
        assertEquals("2001:db8::10" to 8443, parseFirestackEndpoint("[2001:db8::10]:8443", false))
        assertEquals("fe80::1%wlan0" to 53, parseFirestackEndpoint("[fe80::1%wlan0]:53", false))
        assertEquals("2001:db8::20" to 0, parseFirestackEndpoint("[2001:db8::20]", true))
        assertEquals("192.0.2.20" to 0, parseFirestackEndpoint("192.0.2.20:0", true))
    }

    @Test fun rejectsMalformedFlowEndpoints() {
        assertEquals(null, parseFirestackEndpoint("[2001:db8::1]443", false))
        assertEquals(null, parseFirestackEndpoint("not-an-ip:443", false))
        assertEquals(null, parseFirestackEndpoint("192.0.2.1:70000", false))
    }


    @Test
    fun appliesCidrRulesToOriginalDestinationBehindFirestackAlgAddress() {
        val engine = EngineRuntime()
        engine.replaceFlowRules(
            listOf(
                NetworkFlowRule(
                    id = "block-original-subnet",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.USER,
                    reason = "original_destination_blocked",
                    destinationCidr = "203.0.113.0/24",
                ),
            ),
        )
        val adapter = AndroidFlowPolicyAdapter(engine, nowEpochMillis = { 400L })

        val decision = adapter.evaluate(
            flowId = "alg-destination",
            protocolNumber = 6,
            ownerUid = -1,
            sourceAddress = "10.10.10.2",
            sourcePort = 41000,
            destinationAddress = "198.18.0.10",
            destinationPort = 443,
            destinationAddresses = listOf("203.0.113.25"),
        )

        assertEquals(PolicyAction.BLOCK, decision.action)
        assertEquals(1L, engine.flowMonitor.snapshot().blocked)
    }

    @Test
    fun blocksAlgFlowWhenAnyOriginalDestinationMatchesPolicy() {
        val engine = EngineRuntime()
        engine.replaceFlowRules(
            listOf(
                NetworkFlowRule(
                    id = "block-sensitive-range",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.USER,
                    reason = "destination_range_blocked",
                    destinationCidr = "2001:db8:1234::/48",
                ),
            ),
        )
        val adapter = AndroidFlowPolicyAdapter(engine, nowEpochMillis = { 500L })

        val decision = adapter.evaluate(
            flowId = "alg-multiple-destinations",
            protocolNumber = 17,
            ownerUid = -1,
            sourceAddress = "fd00::2",
            sourcePort = 53000,
            destinationAddress = "198.18.0.20",
            destinationPort = 443,
            destinationAddresses = listOf("2001:db8:ffff::1", "2001:db8:1234::53"),
        )

        assertEquals(PolicyAction.BLOCK, decision.action)
        assertEquals(1L, engine.flowMonitor.snapshot().blocked)
    }

}
