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