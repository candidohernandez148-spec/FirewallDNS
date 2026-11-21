package com.firewall.dns.service

import com.firewalldns.engine.android.DnsSocketProtectionProtocol
import com.firewalldns.engine.android.SmoltcpDnsTcpMetrics
import org.junit.Assert.assertEquals
import org.junit.Test

class FirewallDnsTrafficMetricsTest {
    @Test
    fun stoppedTransportClearsLiveAvailabilityAndSessionCount() {
        FirewallDnsTrafficMetrics.smoltcpStarted()
        FirewallDnsTrafficMetrics.smoltcpSnapshot(
            SmoltcpDnsTcpMetrics(
                packetsAccepted = 4,
                ingressRejected = 1,
                sessionsOpened = 2,
                sessionsClosed = 0,
                dataEvents = 2,
                peerHalfCloses = 0,
                responsesQueued = 1,
                responseFailures = 0,
                activeSessions = 2,
                nativeErrors = 0,
            )
        )

        assertEquals(1L, FirewallDnsTrafficMetrics.snapshot().smoltcpTransportAvailable)
        assertEquals(2L, FirewallDnsTrafficMetrics.snapshot().smoltcpSessionsActive)

        FirewallDnsTrafficMetrics.smoltcpStopped()

        val stopped = FirewallDnsTrafficMetrics.snapshot()
        assertEquals(0L, stopped.smoltcpTransportAvailable)
        assertEquals(0L, stopped.smoltcpSessionsActive)
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
}