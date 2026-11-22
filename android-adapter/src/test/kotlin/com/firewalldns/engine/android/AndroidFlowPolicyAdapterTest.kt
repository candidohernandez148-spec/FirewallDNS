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
}
