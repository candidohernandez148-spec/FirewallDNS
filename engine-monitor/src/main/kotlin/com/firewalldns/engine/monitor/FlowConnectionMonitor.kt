package com.firewalldns.engine.monitor

import com.firewalldns.engine.core.FlowProtocol
import com.firewalldns.engine.core.NetworkFlowDecision
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.LongAdder

data class FlowIdentity(
    val id: String,
    val protocol: FlowProtocol,
    val appUid: Int?,
    val appPackage: String?,
    val sourceAddress: String,
    val sourcePort: Int,
    val destinationAddress: String,
    val destinationPort: Int,
    val networkGeneration: Long,
)

data class ActiveFlowSnapshot(
    val identity: FlowIdentity,
    val action: String,
    val reason: String,
    val ruleId: String?,
    val startedAtEpochMillis: Long,
    val lastActivityEpochMillis: Long,
    val bytesSent: Long,
    val bytesReceived: Long,
)

data class FlowMonitorSnapshot(
    val active: Int,
    val opened: Long,
    val closed: Long,
    val blocked: Long,
    val bytesSent: Long,
    val bytesReceived: Long,
    val capacityRejected: Long,
    val flows: List<ActiveFlowSnapshot>,
)

/**
 * Bounded in-memory connection telemetry for the TUN packet-stack adapter.
 * It never performs disk/network I/O. A flow ID can be opened only once while
 * active; networkGeneration lets the host correlate flows with handovers.
 */
class FlowConnectionMonitor(
    private val maxActiveFlows: Int = 4096,
    private val idleTimeoutMillis: Long = 120_000,
) {
    private data class MutableFlow(
        val identity: FlowIdentity,
        val action: String,
        val reason: String,
        val ruleId: String?,
        val startedAt: Long,
        val lastActivity: AtomicLong,
        val sent: LongAdder = LongAdder(),
        val received: LongAdder = LongAdder(),
    ) {
        fun snapshot() = ActiveFlowSnapshot(
            identity, action, reason, ruleId, startedAt, lastActivity.get(), sent.sum(), received.sum(),
        )
    }

    private val active = ConcurrentHashMap<String, MutableFlow>()
    private val opened = LongAdder()
    private val closed = LongAdder()
    private val blocked = LongAdder()
    private val sent = LongAdder()
    private val received = LongAdder()
    private val capacityRejected = LongAdder()

    init {
        require(maxActiveFlows > 0)
        require(idleTimeoutMillis > 0)
    }

    fun open(identity: FlowIdentity, decision: NetworkFlowDecision, nowEpochMillis: Long): Boolean {
        require(identity.id.isNotBlank())
        require(identity.appUid == null || identity.appUid >= 0)
        require(identity.sourcePort in 0..65535 && identity.destinationPort in 1..65535)
        if (decision.action.name == "BLOCK") {
            blocked.increment()
            return true
        }
        if (active.containsKey(identity.id)) return false
        if (active.size >= maxActiveFlows) {
            evictIdle(nowEpochMillis)
            if (active.size >= maxActiveFlows) {
                capacityRejected.increment()
                return false
            }
        }
        val flow = MutableFlow(
            identity, decision.action.name, decision.reason, decision.ruleId,
            nowEpochMillis, AtomicLong(nowEpochMillis),
        )
        val inserted = active.putIfAbsent(identity.id, flow) == null
        if (inserted) opened.increment()
        return inserted
    }

    fun recordBytes(id: String, sentBytes: Long = 0, receivedBytes: Long = 0, nowEpochMillis: Long): Boolean {
        require(sentBytes >= 0 && receivedBytes >= 0)
        val flow = active[id] ?: return false
        flow.sent.add(sentBytes)
        flow.received.add(receivedBytes)
        flow.lastActivity.set(nowEpochMillis)
        sent.add(sentBytes)
        received.add(receivedBytes)
        return true
    }

    fun close(id: String): Boolean {
        val removed = active.remove(id) ?: return false
        closed.increment()
        return true
    }

    fun evictIdle(nowEpochMillis: Long): Int {
        var removed = 0
        active.entries.removeIf { entry ->
            val expired = nowEpochMillis - entry.value.lastActivity.get() >= idleTimeoutMillis
            if (expired) {
                closed.increment()
                removed++
            }
            expired
        }
        return removed
    }

    fun snapshot(): FlowMonitorSnapshot = FlowMonitorSnapshot(
        active = active.size,
        opened = opened.sum(),
        closed = closed.sum(),
        blocked = blocked.sum(),
        bytesSent = sent.sum(),
        bytesReceived = received.sum(),
        capacityRejected = capacityRejected.sum(),
        flows = active.values.map { it.snapshot() }.sortedBy { it.startedAtEpochMillis },
    )
}
