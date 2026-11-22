package com.firewalldns.engine.android

import android.net.Network
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
    private val vpnService: VpnService,
    enableThreatAnalysis: Boolean = true,
    private val onSocketProtectionResult: (DnsSocketProtectionProtocol, Boolean) -> Unit = { _, _ -> },
    private val physicalNetworkProvider: () -> Network? = { null },
) {
    /** Single policy/threat/monitor authority exposed to the Android host. */
    val engine: EngineRuntime = EngineRuntime(
        threatAnalyzer = if (enableThreatAnalysis) ThreatAnalyzer() else ThreatAnalyzer(emptyList(), emptyList())
    )

    private val protectionResult = onSocketProtectionResult

    /**
     * Builds a failover client pinned to the exact physical Network that supplied
     * its resolver list. The Network is captured for this client generation so an
     * in-flight exchange cannot silently bind to a newer Wi-Fi/mobile network.
     */
    fun createDnsFailover(
        upstreams: List<DnsUpstreamConfig>,
        maxAttempts: Int = upstreams.size,
        physicalNetwork: Network? = physicalNetworkProvider(),
    ): DnsUpstreamFailoverClient {
        require(upstreams.isNotEmpty()) { "At least one DNS upstream is required" }
        val socketProtector = AndroidDnsSocketProtector(
            vpnService = vpnService,
            onProtectionResult = protectionResult,
            physicalNetworkProvider = { physicalNetwork },
        )
        return DnsUpstreamFailoverClient(
            upstreams = upstreams.map { config -> DnsUpstreamClient(config, socketProtector) },
            maxAttempts = maxAttempts,
        )
    }
}