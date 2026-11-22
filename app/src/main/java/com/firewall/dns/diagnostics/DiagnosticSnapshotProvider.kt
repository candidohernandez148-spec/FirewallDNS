package com.firewall.dns.diagnostics

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Bundle
import com.firewall.dns.data.repository.FirewallRepository
import com.firewall.dns.service.DnsFirewallService
import com.firewall.dns.service.FirewallDnsTrafficMetrics

/**
 * Read-only, aggregate-only bridge for the companion diagnostic APK.
 * The manifest protects it with a signature-level permission.
 */
class DiagnosticSnapshotProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor {
        require(uri.path == "/snapshot") { "Unsupported diagnostic endpoint" }
        val snapshot = FirewallDnsTrafficMetrics.snapshot()
        val values = linkedMapOf(
            "firewallDnsRunning" to if (FirewallRepository.stats.value.isRunning) 1L else 0L,
            "productionEngine" to FirewallRepository.stats.value.engine,
            "packetsRead" to snapshot.packetsRead,
            "queueRejected" to snapshot.queueRejected,
            "parserRejected" to snapshot.parserRejected,
            "ipv4Packets" to snapshot.ipv4Packets,
            "ipv6Packets" to snapshot.ipv6Packets,
            "dnsTcp" to snapshot.dnsTcp,
            "tcpRstSent" to snapshot.tcpRstSent,
            "tcpRstSuppressed" to snapshot.tcpRstSuppressed,
            "unsupportedTransport" to snapshot.unsupportedTransport,
            "dnsUdpPackets" to snapshot.dnsUdpPackets,
            "malformedDns" to snapshot.malformedDns,
            "dnsRejected" to snapshot.dnsRejected,
            "dnsBlocked" to snapshot.dnsBlocked,
            "dnsObserved" to snapshot.dnsObserved,
            "dnsAllowed" to snapshot.dnsAllowed,
            "cacheHits" to snapshot.cacheHits,
            "cacheMisses" to snapshot.cacheMisses,
            "upstreamSuccess" to snapshot.upstreamSuccess,
            "upstreamFailure" to snapshot.upstreamFailure,
            "upstreamResolvers" to snapshot.upstreamResolvers,
            "upstreamResolverRefreshes" to snapshot.upstreamResolverRefreshes,
            "upstreamResolverUpdatedAtEpochMs" to snapshot.upstreamResolverUpdatedAtEpochMs,
            "upstreamAttemptFailures" to snapshot.upstreamAttemptFailures,
            "upstreamFailureTimeouts" to snapshot.upstreamFailureTimeouts,
            "upstreamFailureProtection" to snapshot.upstreamFailureProtection,
            "upstreamFailureIo" to snapshot.upstreamFailureIo,
            "upstreamFailureValidation" to snapshot.upstreamFailureValidation,
            "upstreamFailureOther" to snapshot.upstreamFailureOther,
            "upstreamCancelled" to snapshot.upstreamCancelled,
            "upstreamProtectUdpAttempts" to snapshot.upstreamProtectUdpAttempts,
            "upstreamProtectUdpSuccess" to snapshot.upstreamProtectUdpSuccess,
            "upstreamProtectUdpFailure" to snapshot.upstreamProtectUdpFailure,
            "upstreamProtectTcpAttempts" to snapshot.upstreamProtectTcpAttempts,
            "upstreamProtectTcpSuccess" to snapshot.upstreamProtectTcpSuccess,
            "upstreamProtectTcpFailure" to snapshot.upstreamProtectTcpFailure,
            "noDnsResponse" to snapshot.noDnsResponse,
            "dnsResponsesBuilt" to snapshot.dnsResponsesBuilt,
            "packetsWritten" to snapshot.packetsWritten,
            "writeErrors" to snapshot.writeErrors,
            "workerErrors" to snapshot.workerErrors,
            "smoltcpTransportAvailable" to snapshot.smoltcpTransportAvailable,
            "smoltcpSessionsActive" to snapshot.smoltcpSessionsActive,
            "smoltcpPacketsAccepted" to snapshot.smoltcpPacketsAccepted,
            "smoltcpSessionsOpened" to snapshot.smoltcpSessionsOpened,
            "smoltcpSessionsClosed" to snapshot.smoltcpSessionsClosed,
            "smoltcpIngressRejected" to snapshot.smoltcpIngressRejected,
            "smoltcpDataEvents" to snapshot.smoltcpDataEvents,
            "smoltcpResponsesQueued" to snapshot.smoltcpResponsesQueued,
            "smoltcpResponseFailures" to snapshot.smoltcpResponseFailures,
            "smoltcpNativeErrors" to snapshot.smoltcpNativeErrors,
            "fragmentsAccepted" to snapshot.fragmentsAccepted,
            "packetsReassembled" to snapshot.packetsReassembled,
            "fragmentsDroppedInvalid" to snapshot.fragmentsDroppedInvalid,
            "fragmentsDroppedLimit" to snapshot.fragmentsDroppedLimit,
            "fragmentAssembliesExpired" to snapshot.fragmentAssembliesExpired,
            "fragmentPendingAssemblies" to snapshot.fragmentPendingAssemblies,
            "fragmentBufferedBytes" to snapshot.fragmentBufferedBytes,
            "firestackActive" to snapshot.firestackActive,
            "flowsActive" to snapshot.flowsActive,
            "flowsOpened" to snapshot.flowsOpened,
            "flowsClosed" to snapshot.flowsClosed,
            "flowsBlocked" to snapshot.flowsBlocked,
            "flowBytesSent" to snapshot.flowBytesSent,
            "flowBytesReceived" to snapshot.flowBytesReceived,
            "flowCapacityRejected" to snapshot.flowCapacityRejected,
            "firestackProtectAttempts" to snapshot.firestackProtectAttempts,
            "firestackProtectSuccess" to snapshot.firestackProtectSuccess,
            "firestackProtectFailure" to snapshot.firestackProtectFailure,
            "firestackBindAttempts" to snapshot.firestackBindAttempts,
            "firestackBindSuccess" to snapshot.firestackBindSuccess,
            "firestackBindFailure" to snapshot.firestackBindFailure,
        )
        return MatrixCursor(arrayOf("metric", "value")).apply {
            values.forEach { (key, value) -> addRow(arrayOf(key, value.toString())) }
        }
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method != "force_tcp_probe") return super.call(method, arg, extras)
        val ctx = context ?: throw IllegalStateException("Provider context unavailable")
        val permission = "com.firewall.dns.permission.READ_DIAGNOSTICS"
        if (ctx.checkCallingPermission(permission) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            throw SecurityException("Signature permission required for diagnostic TCP probe")
        }
        val query = extras?.getByteArray("dns_query")
            ?: throw IllegalArgumentException("dns_query is required")
        return DnsFirewallService.runDiagnosticTcpProbe(query)
    }

    override fun getType(uri: Uri): String = "vnd.android.cursor.dir/vnd.firewalldns.metric"
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0
}
