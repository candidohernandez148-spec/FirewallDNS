package com.firewalldns.engine.android

import android.net.VpnService
import com.firewalldns.engine.dns.DnsUpstreamClient
import com.firewalldns.engine.dns.DnsUpstreamConfig
import com.firewalldns.engine.dns.DnsUpstreamFailoverClient
import com.firewalldns.engine.runtime.EngineRuntime
import com.firewalldns.engine.threat.ThreatAnalyzer

/**
 * Android composition root for the shared decision runtime and DNS upstream.
 *
 * Create this object from the active VpnService and discard it when that
 * service is destroyed. Exchanges block and must run on an I/O dispatcher,
 * never on the VPN packet loop or main thread.
 *
 * This does not create a TUN reader, packet stack, or replace the host VPN.
 */
class AndroidEngineRuntime(
    vpnService: VpnService,
    enableThreatAnalysis: Boolean = true,
    onSocketProtectionResult: (DnsSocketProtectionProtocol, Boolean) -> Unit = { _, _ -> },
) {
    /** Single policy/threat/monitor authority exposed to the Android host. */
    val engine: EngineRuntime = EngineRuntime(
        threatAnalyzer = if (enableThreatAnalysis) ThreatAnalyzer() else ThreatAnalyzer(emptyList(), emptyList())
    )

    private val socketProtector = AndroidDnsSocketProtector(vpnService, onSocketProtectionResult)

    /**
     * Builds a bounded sequential failover client whose UDP and TCP sockets
     * are protected by the active Android VpnService before connect().
     */
    fun createDnsFailover(
        upstreams: List<DnsUpstreamConfig>,
        maxAttempts: Int = upstreams.size,
    ): DnsUpstreamFailoverClient {
        require(upstreams.isNotEmpty()) { "At least one DNS upstream is required" }
        return DnsUpstreamFailoverClient(
            upstreams = upstreams.map { config -> DnsUpstreamClient(config, socketProtector) },
            maxAttempts = maxAttempts,
        )
    }
}