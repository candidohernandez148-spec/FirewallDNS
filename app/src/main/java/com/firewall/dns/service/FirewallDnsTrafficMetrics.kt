package com.firewall.dns.service

import com.firewalldns.engine.android.DnsSocketProtectionProtocol
import com.firewalldns.engine.android.SmoltcpDnsTcpMetrics
import java.util.concurrent.atomic.AtomicLong

/**
 * Aggregate-only counters for the production DNS-only TUN path.
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
        val smoltcpTransportAvailable: Long,
        val smoltcpSessionsActive: Long,
        val smoltcpPacketsAccepted: Long,
        val smoltcpSessionsOpened: Long,
        val smoltcpSessionsClosed: Long,
        val smoltcpIngressRejected: Long,
        val smoltcpDataEvents: Long,
        val smoltcpResponsesQueued: Long,
        val smoltcpResponseFailures: Long,
        val smoltcpNativeErrors: Long,
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
    private val smoltcpTransportAvailable = AtomicLong()
    private val smoltcpSessionsActive = AtomicLong()
    private val smoltcpPacketsAccepted = AtomicLong()
    private val smoltcpSessionsOpened = AtomicLong()
    private val smoltcpSessionsClosed = AtomicLong()
    private val smoltcpIngressRejected = AtomicLong()
    private val smoltcpDataEvents = AtomicLong()
    private val smoltcpResponsesQueued = AtomicLong()
    private val smoltcpResponseFailures = AtomicLong()
    private val smoltcpNativeErrors = AtomicLong()

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
    internal fun smoltcpStarted() { smoltcpTransportAvailable.set(1L) }
    internal fun smoltcpStopped() {
        smoltcpTransportAvailable.set(0L)
        smoltcpSessionsActive.set(0L)
    }
    internal fun smoltcpSnapshot(metrics: SmoltcpDnsTcpMetrics) {
        smoltcpTransportAvailable.set(1L)
        smoltcpSessionsActive.set(metrics.activeSessions.toLong())
        smoltcpPacketsAccepted.set(metrics.packetsAccepted)
        smoltcpSessionsOpened.set(metrics.sessionsOpened)
        smoltcpSessionsClosed.set(metrics.sessionsClosed)
        smoltcpIngressRejected.set(metrics.ingressRejected)
        smoltcpDataEvents.set(metrics.dataEvents)
        smoltcpResponsesQueued.set(metrics.responsesQueued)
        smoltcpResponseFailures.set(metrics.responseFailures)
        smoltcpNativeErrors.set(metrics.nativeErrors)
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
        smoltcpTransportAvailable = smoltcpTransportAvailable.get(),
        smoltcpSessionsActive = smoltcpSessionsActive.get(),
        smoltcpPacketsAccepted = smoltcpPacketsAccepted.get(),
        smoltcpSessionsOpened = smoltcpSessionsOpened.get(),
        smoltcpSessionsClosed = smoltcpSessionsClosed.get(),
        smoltcpIngressRejected = smoltcpIngressRejected.get(),
        smoltcpDataEvents = smoltcpDataEvents.get(),
        smoltcpResponsesQueued = smoltcpResponsesQueued.get(),
        smoltcpResponseFailures = smoltcpResponseFailures.get(),
        smoltcpNativeErrors = smoltcpNativeErrors.get(),
    )
}
