package com.firewall.dns.diagnostics

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
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
            "serviceQueueRejected" to DnsFirewallService.queueRejectedPackets.get(),
            "serviceProcessingErrors" to DnsFirewallService.packetProcessingErrors.get(),
            "serviceWriteErrors" to DnsFirewallService.packetWriteErrors.get(),
        )
        return MatrixCursor(arrayOf("metric", "value")).apply {
            values.forEach { (key, value) -> addRow(arrayOf(key, value.toString())) }
        }
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
