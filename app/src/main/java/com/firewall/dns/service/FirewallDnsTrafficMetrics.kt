package com.firewall.dns.service

import com.firewalldns.engine.android.DnsSocketProtectionProtocol
import com.firewalldns.engine.android.FragmentReassemblerMetrics
import com.firewalldns.engine.monitor.ActiveFlowSnapshot
import com.firewalldns.engine.monitor.FlowMonitorSnapshot
import com.firewalldns.engine.monitor.EngineMetricsSnapshot
import com.firewalldns.engine.android.FirestackNativeStatsSnapshot
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
        val packetsWritten: Long,

        val tunRxBytes: String,
        val tunTxBytes: String,
        val nicRxPackets: Long,
        val nicTxPackets: Long,
        val nicRxBytes: String,
        val nicTxBytes: String,
        val nativeStatsUpdatedAtEpochMs: Long,
        val nicChangeObservedAtEpochMs: Long,
        val ipChangeObservedAtEpochMs: Long,
        val tcpChangeObservedAtEpochMs: Long,
        val udpChangeObservedAtEpochMs: Long,
        val icmpChangeObservedAtEpochMs: Long,
        val forwardChangeObservedAtEpochMs: Long,
        val tunInvalidPackets: Long,
        val tunUnknownL3Packets: Long,
        val tunUnknownL4Packets: Long,
        val tunDrops: Long,
        val ipPacketsReceived: Long,
        val ipPacketsSent: Long,
        val ipInvalidPackets: Long,
        val ipReceiveErrors: Long,
        val ipSendErrors: Long,
        val ipForwardDrops: Long,
        val ipForwardErrors: Long,
        val tcpSegmentsReceived: Long,
        val tcpSegmentsSent: Long,
        val tcpEstablished: Long,
        val tcpConnectFailures: Long,
        val tcpRetransmits: Long,
        val tcpTimeouts: Long,
        val tcpDrops: Long,
        val udpPacketsReceived: Long,
        val udpPacketsSent: Long,
        val udpReceiveErrors: Long,
        val udpDrops: Long,
        val icmpV4Received: Long,
        val icmpV4Sent: Long,
        val icmpV6Received: Long,
        val icmpV6Sent: Long,
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
        val dnsPolicyDecisions: Long,
        val dnsRejected: Long,
        val dnsBlocked: Long,
        val dnsObserved: Long,
        val dnsAllowed: Long,
        val dnsResponseCallbacks: Long,
        val dnsResponseComplete: Long,
        val dnsResponseOtherStatus: Long,
        val dnsResponseCached: Long,
        val dnsResponseLatencySamples: Long,
        val dnsResponseLatencyMsTotal: Long,
        val dnsResponseLastStatus: Long,
        val cacheHits: Long,
        val cacheMisses: Long,
        val engineEventsDropped: Long,
        val engineQueuedEvents: Long,
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
        val lastFlowEventAtEpochMs: Long,
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
        val policyRuleCount: Long,
        val policyRevision: Long,
        val policyInstallFailures: Long,
        val policyInstallStatus: String,
        val lastDnsDomain: String,
        val lastDnsAction: String,
        val lastDnsReason: String,
        val lastDnsDecisionAtEpochMs: Long,
    )

    private val packetsRead = AtomicLong()
    private val packetsWritten = AtomicLong()

    private val tunRxBytes = AtomicReference("—")
    private val tunTxBytes = AtomicReference("—")
    private val nicRxPackets = AtomicLong()
    private val nicTxPackets = AtomicLong()
    private val nicRxBytes = AtomicReference("—")
    private val nicTxBytes = AtomicReference("—")
    private val nativeStatsUpdatedAtEpochMs = AtomicLong()
    private val nicChangeObservedAtEpochMs = AtomicLong()
    private val ipChangeObservedAtEpochMs = AtomicLong()
    private val tcpChangeObservedAtEpochMs = AtomicLong()
    private val udpChangeObservedAtEpochMs = AtomicLong()
    private val icmpChangeObservedAtEpochMs = AtomicLong()
    private val forwardChangeObservedAtEpochMs = AtomicLong()
    private val nicStatsSignature = AtomicReference("")
    private val ipStatsSignature = AtomicReference("")
    private val tcpStatsSignature = AtomicReference("")
    private val udpStatsSignature = AtomicReference("")
    private val icmpStatsSignature = AtomicReference("")
    private val forwardStatsSignature = AtomicReference("")
    private val tunInvalidPackets = AtomicLong()
    private val tunUnknownL3Packets = AtomicLong()
    private val tunUnknownL4Packets = AtomicLong()
    private val tunDrops = AtomicLong()
    private val ipPacketsReceived = AtomicLong()
    private val ipPacketsSent = AtomicLong()
    private val ipInvalidPackets = AtomicLong()
    private val ipReceiveErrors = AtomicLong()
    private val ipSendErrors = AtomicLong()
    private val ipForwardDrops = AtomicLong()
    private val ipForwardErrors = AtomicLong()
    private val tcpSegmentsReceived = AtomicLong()
    private val tcpSegmentsSent = AtomicLong()
    private val tcpEstablished = AtomicLong()
    private val tcpConnectFailures = AtomicLong()
    private val tcpRetransmits = AtomicLong()
    private val tcpTimeouts = AtomicLong()
    private val tcpDrops = AtomicLong()
    private val udpPacketsReceived = AtomicLong()
    private val udpPacketsSent = AtomicLong()
    private val udpReceiveErrors = AtomicLong()
    private val udpDrops = AtomicLong()
    private val icmpV4Received = AtomicLong()
    private val icmpV4Sent = AtomicLong()
    private val icmpV6Received = AtomicLong()
    private val icmpV6Sent = AtomicLong()
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
    private val dnsResponseCallbacks = AtomicLong()
    private val dnsResponseComplete = AtomicLong()
    private val dnsResponseOtherStatus = AtomicLong()
    private val dnsResponseCached = AtomicLong()
    private val dnsResponseLatencySamples = AtomicLong()
    private val dnsResponseLatencyMsTotal = AtomicLong()
    private val dnsResponseLastStatus = AtomicLong(-1L)
    private val cacheHits = AtomicLong()
    private val cacheMisses = AtomicLong()
    private val dnsPolicyDecisions = AtomicLong()
    private val engineEventsDropped = AtomicLong()
    private val engineQueuedEvents = AtomicLong()
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
    private val lastFlowEventAtEpochMs = AtomicLong()
    private val lastFlowEventSignature = AtomicReference("")
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
    private val policyRuleCount = AtomicLong()
    private val policyRevision = AtomicLong()
    private val policyInstallFailures = AtomicLong()
    private val policyInstallStatus = AtomicReference("SIN APLICAR")
    private val lastDnsDomain = AtomicReference("")
    private val lastDnsAction = AtomicReference("")
    private val lastDnsReason = AtomicReference("")
    private val lastDnsDecisionAtEpochMs = AtomicLong()

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
    /**
     * Firestack OnResponse summaries are aggregate-only. The listener may be
     * invoked more than once for a query, so this counts callbacks, not unique queries.
     * Firestack backend status 1 is Complete in the pinned SDK revision.
     */
    internal fun dnsResponse(status: Int, cached: Boolean, latencySeconds: Double) {
        dnsResponseCallbacks.incrementAndGet()
        if (status == 1) dnsResponseComplete.incrementAndGet()
        else dnsResponseOtherStatus.incrementAndGet()
        if (cached) dnsResponseCached.incrementAndGet()
        dnsResponseLastStatus.set(status.toLong())
        if (latencySeconds.isFinite() && latencySeconds >= 0.0 && latencySeconds <= 3600.0) {
            dnsResponseLatencyMsTotal.addAndGet((latencySeconds * 1000.0).toLong())
            dnsResponseLatencySamples.incrementAndGet()
        }
    }
    internal fun cacheHit() { cacheHits.incrementAndGet() }
    internal fun cacheMiss() { cacheMisses.incrementAndGet() }

    internal fun engineMonitorSnapshot(snapshot: EngineMetricsSnapshot) {
        // These values come from the shared policy runtime, not inferred UI events.
        dnsRejected.set(snapshot.rejected)
        cacheHits.set(snapshot.cacheHits)
        cacheMisses.set(snapshot.cacheMisses)
        dnsPolicyDecisions.set(snapshot.decisions)
        engineEventsDropped.set(snapshot.eventsDropped)
        engineQueuedEvents.set(snapshot.queuedEvents.toLong())
    }
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
    internal fun policyRulesApplied(count: Int, revision: Long) {
        policyRuleCount.set(count.coerceAtLeast(0).toLong())
        policyRevision.set(revision.coerceAtLeast(0L))
        policyInstallStatus.set("APLICADAS")
    }
    internal fun policyRulesApplyFailed() {
        policyInstallFailures.incrementAndGet()
        policyInstallStatus.set("ERROR AL APLICAR")
    }
    internal fun dnsDecision(domain: String, action: String, reason: String) {
        lastDnsDomain.set(domain.take(253))
        lastDnsAction.set(action.take(24))
        lastDnsReason.set(reason.take(160))
        lastDnsDecisionAtEpochMs.set(System.currentTimeMillis())
    }
    internal fun firestackStarted() { firestackActive.set(1L) }
    internal fun firestackStopped() {
        firestackActive.set(0L)
        flowsActive.set(0L)
        activeFlows.set(emptyList())
    }
    internal fun flowSnapshot(snapshot: FlowMonitorSnapshot) {
        val signature = "${snapshot.active}:${snapshot.opened}:${snapshot.closed}:${snapshot.blocked}:${snapshot.bytesSent}:${snapshot.bytesReceived}"
        val previousSignature = lastFlowEventSignature.getAndSet(signature)
        if (previousSignature.isNotEmpty() && previousSignature != signature) {
            lastFlowEventAtEpochMs.set(System.currentTimeMillis())
        }
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
    /** Publishes one coherent native Firestack/gVisor snapshot. */
    internal fun firestackNativeSnapshot(stats: FirestackNativeStatsSnapshot) {
        // These timestamps indicate when a changed native counter was observed by
        // polling. Firestack may serve a cached NetStat snapshot, so they are not
        // packet timestamps and are never presented as per-packet capture times.
        val observedAt = stats.sampledAtEpochMs
        fun changed(signature: AtomicReference<String>, next: String): Boolean {
            val previous = signature.getAndSet(next)
            return previous.isNotEmpty() && previous != next
        }
        if (changed(nicStatsSignature, "${stats.nicRxPackets}:${stats.nicTxPackets}:${stats.nicRxBytes}:${stats.nicTxBytes}:${stats.nicInvalidPackets}:${stats.nicDrops}")) nicChangeObservedAtEpochMs.set(observedAt)
        if (changed(ipStatsSignature, "${stats.ipReceived}:${stats.ipSent}:${stats.ipInvalid}:${stats.ipReceiveErrors}:${stats.ipSendErrors}")) ipChangeObservedAtEpochMs.set(observedAt)
        if (changed(tcpStatsSignature, "${stats.tcpReceived}:${stats.tcpSent}:${stats.tcpEstablished}:${stats.tcpConnectFailures}:${stats.tcpRetransmits}:${stats.tcpTimeouts}:${stats.tcpDrops}")) tcpChangeObservedAtEpochMs.set(observedAt)
        if (changed(udpStatsSignature, "${stats.udpReceived}:${stats.udpSent}:${stats.udpReceiveErrors}:${stats.udpDrops}")) udpChangeObservedAtEpochMs.set(observedAt)
        if (changed(icmpStatsSignature, "${stats.icmpV4Received}:${stats.icmpV4Sent}:${stats.icmpV6Received}:${stats.icmpV6Sent}")) icmpChangeObservedAtEpochMs.set(observedAt)
        if (changed(forwardStatsSignature, "${stats.forwardDrops}:${stats.forwardErrors}")) forwardChangeObservedAtEpochMs.set(observedAt)
        tunRxBytes.set(stats.tunReadBytes)
        tunTxBytes.set(stats.tunWrittenBytes)
        nicRxPackets.set(stats.nicRxPackets)
        nicTxPackets.set(stats.nicTxPackets)
        nicRxBytes.set(stats.nicRxBytes)
        nicTxBytes.set(stats.nicTxBytes)
        tunInvalidPackets.set(stats.nicInvalidPackets)
        tunUnknownL3Packets.set(stats.nicUnknownL3)
        tunUnknownL4Packets.set(stats.nicUnknownL4)
        tunDrops.set(stats.nicDrops)
        ipPacketsReceived.set(stats.ipReceived)
        ipPacketsSent.set(stats.ipSent)
        ipInvalidPackets.set(stats.ipInvalid)
        ipReceiveErrors.set(stats.ipReceiveErrors)
        ipSendErrors.set(stats.ipSendErrors)
        ipForwardDrops.set(stats.forwardDrops)
        ipForwardErrors.set(stats.forwardErrors)
        tcpSegmentsReceived.set(stats.tcpReceived)
        tcpSegmentsSent.set(stats.tcpSent)
        tcpEstablished.set(stats.tcpEstablished)
        tcpConnectFailures.set(stats.tcpConnectFailures)
        tcpRetransmits.set(stats.tcpRetransmits)
        tcpTimeouts.set(stats.tcpTimeouts)
        tcpDrops.set(stats.tcpDrops)
        udpPacketsReceived.set(stats.udpReceived)
        udpPacketsSent.set(stats.udpSent)
        udpReceiveErrors.set(stats.udpReceiveErrors)
        udpDrops.set(stats.udpDrops)
        icmpV4Received.set(stats.icmpV4Received)
        icmpV4Sent.set(stats.icmpV4Sent)
        icmpV6Received.set(stats.icmpV6Received)
        icmpV6Sent.set(stats.icmpV6Sent)
        nativeStatsUpdatedAtEpochMs.set(stats.sampledAtEpochMs)
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
        packetsWritten = packetsWritten.get(),

        tunRxBytes = tunRxBytes.get(),
        tunTxBytes = tunTxBytes.get(),
        nicRxPackets = nicRxPackets.get(),
        nicTxPackets = nicTxPackets.get(),
        nicRxBytes = nicRxBytes.get(),
        nicTxBytes = nicTxBytes.get(),
        nativeStatsUpdatedAtEpochMs = nativeStatsUpdatedAtEpochMs.get(),
        nicChangeObservedAtEpochMs = nicChangeObservedAtEpochMs.get(),
        ipChangeObservedAtEpochMs = ipChangeObservedAtEpochMs.get(),
        tcpChangeObservedAtEpochMs = tcpChangeObservedAtEpochMs.get(),
        udpChangeObservedAtEpochMs = udpChangeObservedAtEpochMs.get(),
        icmpChangeObservedAtEpochMs = icmpChangeObservedAtEpochMs.get(),
        forwardChangeObservedAtEpochMs = forwardChangeObservedAtEpochMs.get(),
        tunInvalidPackets = tunInvalidPackets.get(),
        tunUnknownL3Packets = tunUnknownL3Packets.get(),
        tunUnknownL4Packets = tunUnknownL4Packets.get(),
        tunDrops = tunDrops.get(),
        ipPacketsReceived = ipPacketsReceived.get(),
        ipPacketsSent = ipPacketsSent.get(),
        ipInvalidPackets = ipInvalidPackets.get(),
        ipReceiveErrors = ipReceiveErrors.get(),
        ipSendErrors = ipSendErrors.get(),
        ipForwardDrops = ipForwardDrops.get(),
        ipForwardErrors = ipForwardErrors.get(),
        tcpSegmentsReceived = tcpSegmentsReceived.get(),
        tcpSegmentsSent = tcpSegmentsSent.get(),
        tcpEstablished = tcpEstablished.get(),
        tcpConnectFailures = tcpConnectFailures.get(),
        tcpRetransmits = tcpRetransmits.get(),
        tcpTimeouts = tcpTimeouts.get(),
        tcpDrops = tcpDrops.get(),
        udpPacketsReceived = udpPacketsReceived.get(),
        udpPacketsSent = udpPacketsSent.get(),
        udpReceiveErrors = udpReceiveErrors.get(),
        udpDrops = udpDrops.get(),
        icmpV4Received = icmpV4Received.get(),
        icmpV4Sent = icmpV4Sent.get(),
        icmpV6Received = icmpV6Received.get(),
        icmpV6Sent = icmpV6Sent.get(),
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
        dnsPolicyDecisions = dnsPolicyDecisions.get(),
        dnsRejected = dnsRejected.get(),
        dnsBlocked = dnsBlocked.get(),
        dnsObserved = dnsObserved.get(),
        dnsAllowed = dnsAllowed.get(),
        dnsResponseCallbacks = dnsResponseCallbacks.get(),
        dnsResponseComplete = dnsResponseComplete.get(),
        dnsResponseOtherStatus = dnsResponseOtherStatus.get(),
        dnsResponseCached = dnsResponseCached.get(),
        dnsResponseLatencySamples = dnsResponseLatencySamples.get(),
        dnsResponseLatencyMsTotal = dnsResponseLatencyMsTotal.get(),
        dnsResponseLastStatus = dnsResponseLastStatus.get(),
        cacheHits = cacheHits.get(),
        cacheMisses = cacheMisses.get(),
        engineEventsDropped = engineEventsDropped.get(),
        engineQueuedEvents = engineQueuedEvents.get(),
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
        lastFlowEventAtEpochMs = lastFlowEventAtEpochMs.get(),
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
        policyRuleCount = policyRuleCount.get(),
        policyRevision = policyRevision.get(),
        policyInstallFailures = policyInstallFailures.get(),
        policyInstallStatus = policyInstallStatus.get(),
        lastDnsDomain = lastDnsDomain.get(),
        lastDnsAction = lastDnsAction.get(),
        lastDnsReason = lastDnsReason.get(),
        lastDnsDecisionAtEpochMs = lastDnsDecisionAtEpochMs.get(),
    )
}
