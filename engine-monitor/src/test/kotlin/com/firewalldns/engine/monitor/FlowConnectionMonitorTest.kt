package com.firewalldns.engine.monitor

import com.firewalldns.engine.core.FlowProtocol
import com.firewalldns.engine.core.NetworkFlowDecision
import com.firewalldns.engine.core.PolicyAction
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class FlowConnectionMonitorTest {
    private fun identity(id: String) = FlowIdentity(
        id = id,
        protocol = FlowProtocol.TCP,
        appUid = 10234,
        appPackage = "com.example.app",
        sourceAddress = "10.10.10.2",
        sourcePort = 42000,
        destinationAddress = "203.0.113.10",
        destinationPort = 443,
        networkGeneration = 7,
    )

    @Test fun tracksBytesAndClosesFlow() {
        val monitor = FlowConnectionMonitor(maxActiveFlows = 2, idleTimeoutMillis = 100)
        val decision = NetworkFlowDecision(PolicyAction.ALLOW, "no_matching_flow_rule")
        assertTrue(monitor.open(identity("flow-1"), decision, 10))
        assertTrue(monitor.recordBytes("flow-1", sentBytes = 120, receivedBytes = 340, nowEpochMillis = 20))
        val active = monitor.snapshot()
        assertEquals(1, active.active)
        assertEquals(120, active.bytesSent)
        assertEquals(340, active.bytesReceived)
        assertEquals(7L, active.flows.single().identity.networkGeneration)
        assertTrue(monitor.close("flow-1"))
        assertEquals(1, monitor.snapshot().closed)
    }

    @Test fun capacityIsHardBoundedAndIdleFlowsAreEvicted() {
        val monitor = FlowConnectionMonitor(maxActiveFlows = 1, idleTimeoutMillis = 50)
        val decision = NetworkFlowDecision(PolicyAction.ALLOW, "allowed")
        assertTrue(monitor.open(identity("flow-1"), decision, 10))
        assertFalse(monitor.open(identity("flow-2"), decision, 20))
        assertEquals(1L, monitor.snapshot().capacityRejected)
        assertEquals(1, monitor.evictIdle(60))
        assertTrue(monitor.open(identity("flow-2"), decision, 61))
        assertEquals(1, monitor.snapshot().active)
    }

    @Test fun aggregateSnapshotSkipsFlowMaterializationButKeepsCounters() {
        val monitor = FlowConnectionMonitor(maxActiveFlows = 2)
        val decision = NetworkFlowDecision(PolicyAction.ALLOW, "allowed")
        assertTrue(monitor.open(identity("aggregate-flow"), decision, 10))

        val aggregate = monitor.snapshot(includeFlows = false)
        assertEquals(1, aggregate.active)
        assertEquals(1L, aggregate.opened)
        assertTrue(aggregate.flows.isEmpty())
        assertEquals(1, monitor.snapshot().flows.size)
    }

    @Test fun failClosedStackRejectionsAreCountedWithoutInventingAFlow() {
        val monitor = FlowConnectionMonitor()
        monitor.recordBlocked()
        assertEquals(1L, monitor.snapshot().blocked)
        assertEquals(0, monitor.snapshot().active)
        assertTrue(monitor.snapshot().flows.isEmpty())
    }

    @Test fun blockedFlowIsCountedButNeverPublishedAsActive() {
        val monitor = FlowConnectionMonitor()
        val blocked = NetworkFlowDecision(PolicyAction.BLOCK, "user_block", "rule-1")
        assertTrue(monitor.open(identity("blocked"), blocked, 10))
        assertEquals(1L, monitor.snapshot().blocked)
        assertEquals(0, monitor.snapshot().active)
    }
}
