package com.firewall.dns.service

import com.firewalldns.engine.android.DnsSocketProtectionProtocol
import com.firewalldns.engine.core.FlowProtocol
import com.firewalldns.engine.monitor.ActiveFlowSnapshot
import com.firewalldns.engine.monitor.FlowIdentity
import com.firewalldns.engine.monitor.FlowMonitorSnapshot
import com.firewalldns.engine.monitor.EngineMetricsSnapshot
import org.junit.Assert.assertEquals
import org.junit.Test

class FirewallDnsTrafficMetricsTest {
    @Test
    fun firestackSocketBindingAndProtectionFailuresAreSeparated() {
        val before = FirewallDnsTrafficMetrics.snapshot()
        FirewallDnsTrafficMetrics.firestackSocketProtectionResult(true)
        FirewallDnsTrafficMetrics.firestackSocketProtectionResult(false)
        FirewallDnsTrafficMetrics.firestackSocketBindingResult(true)
        FirewallDnsTrafficMetrics.firestackSocketBindingResult(false)
        val after = FirewallDnsTrafficMetrics.snapshot()
        assertEquals(2L, after.firestackProtectAttempts - before.firestackProtectAttempts)
        assertEquals(1L, after.firestackProtectSuccess - before.firestackProtectSuccess)
        assertEquals(1L, after.firestackProtectFailure - before.firestackProtectFailure)
        assertEquals(2L, after.firestackBindAttempts - before.firestackBindAttempts)
        assertEquals(1L, after.firestackBindSuccess - before.firestackBindSuccess)
        assertEquals(1L, after.firestackBindFailure - before.firestackBindFailure)
    }

    @Test
    fun firestackDnsResponseSummariesTrackStatusCacheAndValidLatency() {
        val before = FirewallDnsTrafficMetrics.snapshot()
        FirewallDnsTrafficMetrics.dnsResponse(status = 1, cached = true, latencySeconds = 0.025)
        FirewallDnsTrafficMetrics.dnsResponse(status = 2, cached = false, latencySeconds = Double.NaN)

        val after = FirewallDnsTrafficMetrics.snapshot()
        assertEquals(2L, after.dnsResponseCallbacks - before.dnsResponseCallbacks)
        assertEquals(1L, after.dnsResponseComplete - before.dnsResponseComplete)
        assertEquals(1L, after.dnsResponseOtherStatus - before.dnsResponseOtherStatus)
        assertEquals(1L, after.dnsResponseCached - before.dnsResponseCached)
        assertEquals(1L, after.dnsResponseLatencySamples - before.dnsResponseLatencySamples)
        assertEquals(25L, after.dnsResponseLatencyMsTotal - before.dnsResponseLatencyMsTotal)
        assertEquals(2L, after.dnsResponseLastStatus)
    }

    @Test
    fun firestackAndFlowTelemetryAreExposedInSnapshots() {
        val before = FirewallDnsTrafficMetrics.snapshot()
        FirewallDnsTrafficMetrics.firestackStarted()
        FirewallDnsTrafficMetrics.flowSnapshot(
            FlowMonitorSnapshot(
                active = 3,
                opened = 12,
                closed = 9,
                blocked = 4,
                bytesSent = 1024,
                bytesReceived = 2048,
                capacityRejected = 2,
                flows = emptyList(),
            ),
        )
        val after = FirewallDnsTrafficMetrics.snapshot()
        assertEquals(1L, after.firestackActive)
        assertEquals(3L, after.flowsActive)
        assertEquals(12L, after.flowsOpened)
        assertEquals(9L, after.flowsClosed)
        assertEquals(4L, after.flowsBlocked)
        assertEquals(1024L, after.flowBytesSent)
        assertEquals(2048L, after.flowBytesReceived)
        assertEquals(2L, after.flowCapacityRejected)
        FirewallDnsTrafficMetrics.firestackStopped()
        assertEquals(0L, FirewallDnsTrafficMetrics.snapshot().firestackActive)
        assertEquals(0L, FirewallDnsTrafficMetrics.snapshot().flowsActive)
    }


    @Test
    fun activeFlowDetailsAreCollectedOnlyWhenRequestedWithoutStoppingAggregates() {
        val flow = ActiveFlowSnapshot(
            identity = FlowIdentity(
                id = "flow-1",
                protocol = FlowProtocol.TCP,
                appUid = 10001,
                appPackage = "com.example.app",
                sourceAddress = "10.0.0.2",
                sourcePort = 45000,
                destinationAddress = "203.0.113.10",
                destinationPort = 443,
                networkGeneration = 1,
            ),
            action = "ALLOW",
            reason = "test",
            ruleId = null,
            startedAtEpochMillis = 1,
            lastActivityEpochMillis = 2,
            bytesSent = 10,
            bytesReceived = 20,
        )

        FirewallDnsTrafficMetrics.setActiveFlowDetailsRequested(false)
        FirewallDnsTrafficMetrics.flowSnapshot(
            FlowMonitorSnapshot(1, 1, 0, 0, 10, 20, 0, listOf(flow)),
        )
        var snapshot = FirewallDnsTrafficMetrics.snapshot()
        assertEquals(1L, snapshot.flowsActive)
        assertEquals(emptyList<ActiveFlowSnapshot>(), snapshot.activeFlows)
        assertEquals(false, FirewallDnsTrafficMetrics.shouldCollectActiveFlowDetails())

        FirewallDnsTrafficMetrics.setActiveFlowDetailsRequested(true)
        FirewallDnsTrafficMetrics.flowSnapshot(
            FlowMonitorSnapshot(1, 1, 0, 0, 10, 20, 0, listOf(flow)),
        )
        snapshot = FirewallDnsTrafficMetrics.snapshot()
        assertEquals(true, FirewallDnsTrafficMetrics.shouldCollectActiveFlowDetails())
        assertEquals(listOf(flow), snapshot.activeFlows)
        assertEquals(1L, snapshot.flowsActive)

        FirewallDnsTrafficMetrics.setActiveFlowDetailsRequested(false)
        assertEquals(emptyList<ActiveFlowSnapshot>(), FirewallDnsTrafficMetrics.snapshot().activeFlows)
        assertEquals(1L, FirewallDnsTrafficMetrics.snapshot().flowsActive)
    }

    @Test
    fun socketProtectionOutcomesAreCountedSeparatelyForUdpAndTcp() {
        val before = FirewallDnsTrafficMetrics.snapshot()
        FirewallDnsTrafficMetrics.socketProtectionResult(DnsSocketProtectionProtocol.UDP, true)
        FirewallDnsTrafficMetrics.socketProtectionResult(DnsSocketProtectionProtocol.UDP, false)
        FirewallDnsTrafficMetrics.socketProtectionResult(DnsSocketProtectionProtocol.TCP, true)

        val after = FirewallDnsTrafficMetrics.snapshot()
        assertEquals(2L, after.upstreamProtectUdpAttempts - before.upstreamProtectUdpAttempts)
        assertEquals(1L, after.upstreamProtectUdpSuccess - before.upstreamProtectUdpSuccess)
        assertEquals(1L, after.upstreamProtectUdpFailure - before.upstreamProtectUdpFailure)
        assertEquals(1L, after.upstreamProtectTcpAttempts - before.upstreamProtectTcpAttempts)
        assertEquals(1L, after.upstreamProtectTcpSuccess - before.upstreamProtectTcpSuccess)
        assertEquals(0L, after.upstreamProtectTcpFailure - before.upstreamProtectTcpFailure)
    }
    @Test
    fun upstreamAttemptFailuresAreClassifiedWithoutCountingCancellationAsFailure() {
        val before = FirewallDnsTrafficMetrics.snapshot()
        FirewallDnsTrafficMetrics.upstreamAttemptFailure("dns_upstream_udp_timeout")
        FirewallDnsTrafficMetrics.upstreamAttemptFailure("dns_upstream_tcp_socket_protection_failed")
        FirewallDnsTrafficMetrics.upstreamAttemptFailure("dns_upstream_tcp_io_error")
        FirewallDnsTrafficMetrics.upstreamAttemptFailure("dns_upstream_response_question_mismatch")
        FirewallDnsTrafficMetrics.upstreamAttemptFailure("unexpected_failure")
        FirewallDnsTrafficMetrics.upstreamCancelled()

        val after = FirewallDnsTrafficMetrics.snapshot()
        assertEquals(5L, after.upstreamAttemptFailures - before.upstreamAttemptFailures)
        assertEquals(1L, after.upstreamFailureTimeouts - before.upstreamFailureTimeouts)
        assertEquals(1L, after.upstreamFailureProtection - before.upstreamFailureProtection)
        assertEquals(1L, after.upstreamFailureIo - before.upstreamFailureIo)
        assertEquals(1L, after.upstreamFailureValidation - before.upstreamFailureValidation)
        assertEquals(1L, after.upstreamFailureOther - before.upstreamFailureOther)
        assertEquals(1L, after.upstreamCancelled - before.upstreamCancelled)
        assertEquals(0L, after.upstreamFailure - before.upstreamFailure)
    }

    @Test
    fun engineMonitorSnapshotFeedsDnsCacheRejectionAndQueueCounters() {
        FirewallDnsTrafficMetrics.engineMonitorSnapshot(
            EngineMetricsSnapshot(
                decisions = 21,
                blocked = 5,
                observed = 3,
                allowed = 13,
                rejected = 2,
                cacheHits = 8,
                cacheMisses = 13,
                eventsDropped = 4,
                queuedEvents = 7,
            ),
        )

        val snapshot = FirewallDnsTrafficMetrics.snapshot()
        assertEquals(2L, snapshot.dnsRejected)
        assertEquals(8L, snapshot.cacheHits)
        assertEquals(13L, snapshot.cacheMisses)
        assertEquals(4L, snapshot.engineEventsDropped)
        assertEquals(7L, snapshot.engineQueuedEvents)
    }

    @Test
    fun upstreamResolverChangesAreExposedAndCountOnlyWhenListChanges() {
        val before = FirewallDnsTrafficMetrics.snapshot()
        FirewallDnsTrafficMetrics.upstreamResolversChanged(listOf("192.168.1.1", "1.1.1.1"))
        FirewallDnsTrafficMetrics.upstreamResolversChanged(listOf("192.168.1.1", "1.1.1.1"))
        val unchanged = FirewallDnsTrafficMetrics.snapshot()
        assertEquals("192.168.1.1,1.1.1.1", unchanged.upstreamResolvers)
        assertEquals(1L, unchanged.upstreamResolverRefreshes - before.upstreamResolverRefreshes)
        assertEquals(true, unchanged.upstreamResolverUpdatedAtEpochMs > 0L)
        FirewallDnsTrafficMetrics.upstreamResolversChanged(listOf("8.8.8.8"))
        val changed = FirewallDnsTrafficMetrics.snapshot()
        assertEquals("8.8.8.8", changed.upstreamResolvers)
        assertEquals(2L, changed.upstreamResolverRefreshes - before.upstreamResolverRefreshes)
    }
}