package com.firewalldns.engine.android

import android.net.VpnService
import com.firewalldns.engine.dns.DnsSocketProtector
import java.net.DatagramSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicLong

data class AndroidSocketProtectionSnapshot(
    val datagramAttempts: Long,
    val datagramSuccesses: Long,
    val datagramFailures: Long,
    val streamAttempts: Long,
    val streamSuccesses: Long,
    val streamFailures: Long,
)

/** Aggregate-only protect() outcome counters; no addresses or payloads are retained. */
object AndroidSocketProtectionMetrics {
    private val datagramAttempts = AtomicLong()
    private val datagramSuccesses = AtomicLong()
    private val datagramFailures = AtomicLong()
    private val streamAttempts = AtomicLong()
    private val streamSuccesses = AtomicLong()
    private val streamFailures = AtomicLong()

    internal fun recordDatagram(success: Boolean) {
        datagramAttempts.incrementAndGet()
        if (success) datagramSuccesses.incrementAndGet() else datagramFailures.incrementAndGet()
    }

    internal fun recordStream(success: Boolean) {
        streamAttempts.incrementAndGet()
        if (success) streamSuccesses.incrementAndGet() else streamFailures.incrementAndGet()
    }

    fun snapshot() = AndroidSocketProtectionSnapshot(
        datagramAttempts = datagramAttempts.get(),
        datagramSuccesses = datagramSuccesses.get(),
        datagramFailures = datagramFailures.get(),
        streamAttempts = streamAttempts.get(),
        streamSuccesses = streamSuccesses.get(),
        streamFailures = streamFailures.get(),
    )
}

/**
 * Android boundary for excluding DNS upstream sockets from the active VPN.
 * Both overloads are called before connect(); a false or thrown protect()
 * result is counted and remains fail-closed in DnsUpstreamClient.
 */
class AndroidDnsSocketProtector(
    private val vpnService: VpnService,
) : DnsSocketProtector {

    override fun protect(socket: DatagramSocket): Boolean {
        val protected = runCatching { vpnService.protect(socket) }.getOrDefault(false)
        AndroidSocketProtectionMetrics.recordDatagram(protected)
        return protected
    }

    override fun protect(socket: Socket): Boolean {
        val protected = runCatching { vpnService.protect(socket) }.getOrDefault(false)
        AndroidSocketProtectionMetrics.recordStream(protected)
        return protected
    }
}
