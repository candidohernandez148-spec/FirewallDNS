package com.firewall.dns.service

import com.firewalldns.engine.android.DnsSocketProtectionProtocol
import com.firewalldns.engine.android.FragmentReassemblerMetrics
import com.firewalldns.engine.monitor.ActiveFlowSnapshot
import com.firewalldns.engine.monitor.FlowMonitorSnapshot
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Aggregate-only counters for the production Firestack TUN and DNS policy paths.
 *
 * No packet bytes, IP addresses, domains, UIDs, or package names are retained.
 * Counters are process-local and can be sampled without blocking packet workers.
 */
object FirewallDnsTrafficMetrics {
    data class Snapshot(
        val packetsRead: Long,
        val queueRejected: Long,
        val parserRejected: Long,
        val ipv4Packets: Long,
        val ipv6Packets: Long,
        val nonDnsTcp: Long,
        val nonDnsUdp: Long,
        val dnsTcp: Long,
        val tcpRstSent: Long,
        val tcpRstSuppressed: Long,
        val unsupportedTransport: Long,
        val dnsUdpPackets: Long,
        val malformedDns: Long,
        val dnsRejected: Long,
        val dnsBlocked: Long,
        val dnsObserved: Long,
        val dnsAllowed: Long,
        val cacheHits: Long,
        val cacheMisses: Long,
        val upstreamSuccess: Long,
        val upstreamFailure: Long,
        val upstreamResolvers: String,
        val upstreamResolverRefreshes: Long,
        val upstreamResolverUpdatedAtEpochMs: Long,
        val upstreamAttemptFailures: Long,
        val upstreamFailureTimeouts: Long,
        val upstreamFailureProtection: Long,
        val upstreamFailureIo: Long,
        val upstreamFailureValidation: Long,
        val upstreamFailureOther: Long,
        val upstreamCancelled: Long,
        val upstreamProtectUdpAttempts: Long,
        val upstreamProtectUdpSuccess: Long,
        val upstreamProtectUdpFailure: Long,
        val upstreamProtectTcpAttempts: Long,
        val upstreamProtectTcpSuccess: Long,
        val upstreamProtectTcpFailure: Long,
        val noDnsResponse: Long,
        val dnsResponsesBuilt: Long,
        val packetsWritten: Long,
        val writeErrors: Long,
        val workerErrors: Long,
        val fragmentsAccepted: Long,
        val packetsReassembled: Long,
        val fragmentsDroppedInvalid: Long,
        val fragmentsDroppedLimit: Long,
        val fragmentAssembliesExpired: Long,
        val fragmentPendingAssemblies: Long,
        val fragmentBufferedBytes: Long,
        val firestackActive: Long,
        val flowsActive: Long,
        val activeFlows: List<ActiveFlowSnapshot>,
        val flowsOpened: Long,
        val flowsClosed: Long,
        val flowsBlocked: Long,
        val flowBytesSent: Long,
        val flowBytesReceived: Long,
        val flowCapacityRejected: Long,
        val firestackProtectAttempts: Long,
        val firestackProtectSuccess: Long,
        val firestackProtectFailure: Long,
        val firestackBindAttempts: Long,
        val firestackBindSuccess: Long,
        val firestackBindFailure: Long,
    )

    private val packetsRead = AtomicLong()
    private val queueRejected = AtomicLong()
    private val parserRejected = AtomicLong()
    private val ipv4Packets = AtomicLong()
    private val ipv6Packets = AtomicLong()
    private val nonDnsTcp = AtomicLong()
    private val nonDnsUdp = AtomicLong()
    private val dnsTcp = AtomicLong()
    private val tcpRstSent = AtomicLong()
    private val tcpRstSuppressed = AtomicLong()
    private val unsupportedTransport = AtomicLong()
    private val dnsUdpPackets = AtomicLong()
    private val malformedDns = AtomicLong()
    private val dnsRejected = AtomicLong()
    private val dnsBlocked = AtomicLong()
    private val dnsObserved = AtomicLong()
    private val dnsAllowed = AtomicLong()
    private val cacheHits = AtomicLong()
    private val cacheMisses = AtomicLong()
    private val upstreamSuccess = AtomicLong()
    private val upstreamFailure = AtomicLong()
    private val upstreamResolvers = AtomicReference("")
    private val upstreamResolverRefreshes = AtomicLong()
    private val upstreamResolverUpdatedAtEpochMs = AtomicLong()
    private val upstreamAttemptFailures = AtomicLong()
    private val upstreamFailureTimeouts = AtomicLong()
    private val upstreamFailureProtection = AtomicLong()
    private val upstreamFailureIo = AtomicLong()
    private val upstreamFailureValidation = AtomicLong()
    private val upstreamFailureOther = AtomicLong()
    private val upstreamCancelled = AtomicLong()
    private val upstreamProtectUdpAttempts = AtomicLong()
    private val upstreamProtectUdpSuccess = AtomicLong()
    private val upstreamProtectUdpFailure = AtomicLong()
    private val upstreamProtectTcpAttempts = AtomicLong()
    private val upstreamProtectTcpSuccess = AtomicLong()
    private val upstreamProtectTcpFailure = AtomicLong()
    private val noDnsResponse = AtomicLong()
    private val dnsResponsesBuilt = AtomicLong()
    private val packetsWritten = AtomicLong()
    private val writeErrors = AtomicLong()
    private val workerErrors = AtomicLong()
    private val fragmentsAccepted = AtomicLong()
    private val packetsReassembled = AtomicLong()
    private val fragmentsDroppedInvalid = AtomicLong()
    private val fragmentsDroppedLimit = AtomicLong()
    private val fragmentAssembliesExpired = AtomicLong()
    private val fragmentPendingAssemblies = AtomicLong()
    private val fragmentBufferedBytes = AtomicLong()
    private val firestackActive = AtomicLong()
    private val activeFlows = AtomicReference<List<ActiveFlowSnapshot>>(emptyList())
    private val flowsActive = AtomicLong()
    private val flowsOpened = AtomicLong()
    private val flowsClosed = AtomicLong()
    private val flowsBlocked = AtomicLong()
    private val flowBytesSent = AtomicLong()
    private val flowBytesReceived = AtomicLong()
    private val flowCapacityRejected = AtomicLong()
    private val firestackProtectAttempts = AtomicLong()
    private val firestackProtectSuccess = AtomicLong()
    private val firestackProtectFailure = AtomicLong()
    private val firestackBindAttempts = AtomicLong()
    private val firestackBindSuccess = AtomicLong()
    private val firestackBindFailure = AtomicLong()

    internal fun packetRead() { packetsRead.incrementAndGet() }
    internal fun queueRejected() { queueRejected.incrementAndGet() }
    internal fun parserRejected() { parserRejected.incrementAndGet() }
    internal fun ipv4Packet() { ipv4Packets.incrementAndGet() }
    internal fun ipv6Packet() { ipv6Packets.incrementAndGet() }
    internal fun nonDnsTcp() { nonDnsTcp.incrementAndGet() }
    internal fun nonDnsUdp() { nonDnsUdp.incrementAndGet() }
    internal fun tcpDns() { dnsTcp.incrementAndGet() }
    internal fun tcpRstSent() { tcpRstSent.incrementAndGet() }
    internal fun tcpRstSuppressed() { tcpRstSuppressed.incrementAndGet() }
    internal fun unsupportedTransport() { unsupportedTransport.incrementAndGet() }
    internal fun dnsUdpPacket() { dnsUdpPackets.incrementAndGet() }
    internal fun malformedDns() { malformedDns.incrementAndGet() }
    internal fun dnsRejected() { dnsRejected.incrementAndGet() }
    internal fun dnsBlocked() { dnsBlocked.incrementAndGet() }
    internal fun dnsObserved() { dnsObserved.incrementAndGet() }
    internal fun dnsAllowed() { dnsAllowed.incrementAndGet() }
    internal fun cacheHit() { cacheHits.incrementAndGet() }
    internal fun cacheMiss() { cacheMisses.incrementAndGet() }
    internal fun upstreamSuccess() { upstreamSuccess.incrementAndGet() }
    internal fun upstreamFailure() { upstreamFailure.incrementAndGet() }
    internal fun upstreamResolversChanged(servers: List<String>) {
        val value = servers.joinToString(",")
        if (upstreamResolvers.getAndSet(value) != value) {
            upstreamResolverRefreshes.incrementAndGet()
            upstreamResolverUpdatedAtEpochMs.set(System.currentTimeMillis())
        }
    }
    internal fun upstreamAttemptFailure(reason: String) {
        upstreamAttemptFailures.incrementAndGet()
        when {
            reason.contains("timeout", ignoreCase = true) ->
                upstreamFailureTimeouts.incrementAndGet()
            reason.contains("protection", ignoreCase = true) ||
                reason.contains("security", ignoreCase = true) ->
                upstreamFailureProtection.incrementAndGet()
            reason.contains("io_error", ignoreCase = true) ||
                reason.contains("incomplete", ignoreCase = true) ->
                upstreamFailureIo.incrementAndGet()
            reason.startsWith("dns_upstream_response_") ||
                reason.startsWith("dns_upstream_question_") ||
                reason.startsWith("dns_upstream_record_") ||
                reason.contains("mismatch", ignoreCase = true) ||
                reason.contains("malformed", ignoreCase = true) ||
                reason.contains("truncated", ignoreCase = true) ->
                upstreamFailureValidation.incrementAndGet()
            else -> upstreamFailureOther.incrementAndGet()
        }
    }
    internal fun upstreamCancelled() { upstreamCancelled.incrementAndGet() }
    internal fun socketProtectionResult(protocol: DnsSocketProtectionProtocol, wasProtected: Boolean) {
        val attempts = if (protocol == DnsSocketProtectionProtocol.UDP) upstreamProtectUdpAttempts else upstreamProtectTcpAttempts
        val successes = if (protocol == DnsSocketProtectionProtocol.UDP) upstreamProtectUdpSuccess else upstreamProtectTcpSuccess
        val failures = if (protocol == DnsSocketProtectionProtocol.UDP) upstreamProtectUdpFailure else upstreamProtectTcpFailure
        attempts.incrementAndGet()
        if (wasProtected) successes.incrementAndGet() else failures.incrementAndGet()
    }
    internal fun noDnsResponse() { noDnsResponse.incrementAndGet() }
    internal fun responseBuilt() { dnsResponsesBuilt.incrementAndGet() }
    internal fun responseWritten() { packetsWritten.incrementAndGet() }
    internal fun writeError() { writeErrors.incrementAndGet() }
    internal fun workerError() { workerErrors.incrementAndGet() }
    internal fun firestackSocketProtectionResult(success: Boolean) {
        firestackProtectAttempts.incrementAndGet()
        if (success) firestackProtectSuccess.incrementAndGet() else firestackProtectFailure.incrementAndGet()
    }
    internal fun firestackSocketBindingResult(success: Boolean) {
        firestackBindAttempts.incrementAndGet()
        if (success) firestackBindSuccess.incrementAndGet() else firestackBindFailure.incrementAndGet()
    }
    internal fun firestackStarted() { firestackActive.set(1L) }
    internal fun firestackStopped() {
        firestackActive.set(0L)
        flowsActive.set(0L)
        activeFlows.set(emptyList())
    }
    internal fun flowSnapshot(snapshot: FlowMonitorSnapshot) {
        flowsActive.set(snapshot.active.toLong())
        if (snapshot.flows.isNotEmpty() || snapshot.active == 0) {
            activeFlows.set(snapshot.flows)
        }
        flowsOpened.set(snapshot.opened)
        flowsClosed.set(snapshot.closed)
        flowsBlocked.set(snapshot.blocked)
        flowBytesSent.set(snapshot.bytesSent)
        flowBytesReceived.set(snapshot.bytesReceived)
        flowCapacityRejected.set(snapshot.capacityRejected)
    }
    internal fun fragmentSnapshot(metrics: FragmentReassemblerMetrics) {
        fragmentsAccepted.set(metrics.fragmentsAccepted)
        packetsReassembled.set(metrics.packetsReassembled)
        fragmentsDroppedInvalid.set(metrics.fragmentsDroppedInvalid)
        fragmentsDroppedLimit.set(metrics.fragmentsDroppedLimit)
        fragmentAssembliesExpired.set(metrics.assembliesExpired)
        fragmentPendingAssemblies.set(metrics.pendingAssemblies.toLong())
        fragmentBufferedBytes.set(metrics.bufferedBytes.toLong())
    }

    /** Returns a non-blocking point-in-time aggregate snapshot for UI/diagnostics. */
    fun snapshot(): Snapshot = Snapshot(
        packetsRead = packetsRead.get(),
        queueRejected = queueRejected.get(),
        parserRejected = parserRejected.get(),
        ipv4Packets = ipv4Packets.get(),
        ipv6Packets = ipv6Packets.get(),
        nonDnsTcp = nonDnsTcp.get(),
        nonDnsUdp = nonDnsUdp.get(),
        dnsTcp = dnsTcp.get(),
        tcpRstSent = tcpRstSent.get(),
        tcpRstSuppressed = tcpRstSuppressed.get(),
        unsupportedTransport = unsupportedTransport.get(),
        dnsUdpPackets = dnsUdpPackets.get(),
        malformedDns = malformedDns.get(),
        dnsRejected = dnsRejected.get(),
        dnsBlocked = dnsBlocked.get(),
        dnsObserved = dnsObserved.get(),
        dnsAllowed = dnsAllowed.get(),
        cacheHits = cacheHits.get(),
        cacheMisses = cacheMisses.get(),
        upstreamSuccess = upstreamSuccess.get(),
        upstreamFailure = upstreamFailure.get(),
        upstreamResolvers = upstreamResolvers.get(),
        upstreamResolverRefreshes = upstreamResolverRefreshes.get(),
        upstreamResolverUpdatedAtEpochMs = upstreamResolverUpdatedAtEpochMs.get(),
        upstreamAttemptFailures = upstreamAttemptFailures.get(),
        upstreamFailureTimeouts = upstreamFailureTimeouts.get(),
        upstreamFailureProtection = upstreamFailureProtection.get(),
        upstreamFailureIo = upstreamFailureIo.get(),
        upstreamFailureValidation = upstreamFailureValidation.get(),
        upstreamFailureOther = upstreamFailureOther.get(),
        upstreamCancelled = upstreamCancelled.get(),
        upstreamProtectUdpAttempts = upstreamProtectUdpAttempts.get(),
        upstreamProtectUdpSuccess = upstreamProtectUdpSuccess.get(),
        upstreamProtectUdpFailure = upstreamProtectUdpFailure.get(),
        upstreamProtectTcpAttempts = upstreamProtectTcpAttempts.get(),
        upstreamProtectTcpSuccess = upstreamProtectTcpSuccess.get(),
        upstreamProtectTcpFailure = upstreamProtectTcpFailure.get(),
        noDnsResponse = noDnsResponse.get(),
        dnsResponsesBuilt = dnsResponsesBuilt.get(),
        packetsWritten = packetsWritten.get(),
        writeErrors = writeErrors.get(),
        workerErrors = workerErrors.get(),
        fragmentsAccepted = fragmentsAccepted.get(),
        packetsReassembled = packetsReassembled.get(),
        fragmentsDroppedInvalid = fragmentsDroppedInvalid.get(),
        fragmentsDroppedLimit = fragmentsDroppedLimit.get(),
        fragmentAssembliesExpired = fragmentAssembliesExpired.get(),
        fragmentPendingAssemblies = fragmentPendingAssemblies.get(),
        fragmentBufferedBytes = fragmentBufferedBytes.get(),
        firestackActive = firestackActive.get(),
        flowsActive = flowsActive.get(),
        activeFlows = activeFlows.get(),
        flowsOpened = flowsOpened.get(),
        flowsClosed = flowsClosed.get(),
        flowsBlocked = flowsBlocked.get(),
        flowBytesSent = flowBytesSent.get(),
        flowBytesReceived = flowBytesReceived.get(),
        flowCapacityRejected = flowCapacityRejected.get(),
        firestackProtectAttempts = firestackProtectAttempts.get(),
        firestackProtectSuccess = firestackProtectSuccess.get(),
        firestackProtectFailure = firestackProtectFailure.get(),
        firestackBindAttempts = firestackBindAttempts.get(),
        firestackBindSuccess = firestackBindSuccess.get(),
        firestackBindFailure = firestackBindFailure.get(),
    )
}
