package com.firewalldns.engine.android

import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.celzero.firestack.backend.Backend
import com.celzero.firestack.backend.DNSOpts
import com.celzero.firestack.backend.DNSSummary
import com.celzero.firestack.backend.DomainOpts
import com.celzero.firestack.backend.ServerSummary
import com.celzero.firestack.backend.Tab
import com.celzero.firestack.intra.Bridge
import com.celzero.firestack.intra.FlowSummary
import com.celzero.firestack.intra.Intra
import com.celzero.firestack.intra.Mark
import com.celzero.firestack.intra.PreMark
import com.celzero.firestack.intra.Tunnel
import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.NetworkFlowDecision
import com.firewalldns.engine.core.RuleSource
import com.firewalldns.engine.monitor.FlowMonitorSnapshot
import com.firewalldns.engine.runtime.EngineRuntime
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns the Firestack/gVisor user-space network stack attached to the existing
 * Android VpnService TUN. It never creates a second VPN or reads the TUN fd.
 */
class FirestackTunnelAdapter private constructor(
    private val tunReference: ParcelFileDescriptor,
    private val tunnel: Tunnel,
    private val bridge: FirewallDNSFirestackBridge,
    private var currentLinkMtu: Int,
) : AutoCloseable {

    private val closed = AtomicBoolean(false)

    @Synchronized
    fun updatePhysicalNetworkResolver(resolver: String, linkMtu: Int): Boolean {
        if (closed.get()) return false
        if (linkMtu !in 576..9000) return false
        val address = formatHostPort(resolver)
        val dnsUpdated = runCatching {
            Intra.addDefaultTransport(tunnel, Backend.DNS53, address, "")
            true
        }.getOrDefault(false)
        return updateLinkMtu(linkMtu) && dnsUpdated
    }

    @Synchronized
    fun updateLinkMtu(linkMtu: Int): Boolean {
        if (closed.get() || linkMtu !in 576..9000) return false
        if (linkMtu == currentLinkMtu) return true
        val updated = runCatching { tunnel.setLinkMtu(linkMtu.toLong()) }.getOrDefault(false)
        if (updated) currentLinkMtu = linkMtu
        return updated
    }

    fun isConnected(): Boolean = !closed.get() && runCatching { tunnel.isConnected() }.getOrDefault(false)

    fun stat() = runCatching { tunnel.stat() }.getOrNull()

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { tunnel.disconnect() }
        runCatching { bridge.close() }
        runCatching { tunReference.close() }
    }

    companion object {
        private const val TUN_IFADDRS = "10.10.10.2/32,fd00:10:10::2/128"
        private const val FAKE_DNS = "10.10.10.1:53,[fd00:10:10::1]:53"

        fun connect(
            vpnService: VpnService,
            tunDescriptor: ParcelFileDescriptor,
            mtu: Int,
            linkMtu: Int,
            resolver: String,
            engine: EngineRuntime,
            flowPolicyAdapter: AndroidFlowPolicyAdapter,
            physicalNetworkProvider: () -> Network?,
            isUidBlocked: (Int) -> Boolean = { false },
            onDnsDecision: (String, Int, Int?, String, PolicyAction) -> Unit = { _, _, _, _, _ -> },
            onSocketProtectionResult: (Boolean) -> Unit = {},
            onSocketBindingResult: (Boolean) -> Unit = {},
            onFlowSnapshot: (FlowMonitorSnapshot) -> Unit = {},
        ): FirestackTunnelAdapter {
            require(mtu in 576..9000) { "Invalid TUN MTU" }
            require(linkMtu in 576..9000) { "Invalid physical link MTU" }
            val tunReference = ParcelFileDescriptor.dup(tunDescriptor.fileDescriptor)
            var bridge: FirewallDNSFirestackBridge? = null
            var createdTunnel: Tunnel? = null
            try {
                bridge = FirewallDNSFirestackBridge(
                    vpnService = vpnService,
                    engine = engine,
                    flowPolicyAdapter = flowPolicyAdapter,
                    physicalNetworkProvider = physicalNetworkProvider,
                    isUidBlocked = isUidBlocked,
                    onDnsDecision = onDnsDecision,
                    onSocketProtectionResult = onSocketProtectionResult,
                    onSocketBindingResult = onSocketBindingResult,
                    onFlowSnapshot = onFlowSnapshot,
                )
                // Patched Firestack mode redirects every UDP/TCP port-53 destination to DNS policy.
                Intra.captureDnsPort()
                val defaultDns = Intra.newDefaultDNS(
                    Backend.DNS53,
                    formatHostPort(resolver),
                    "",
                )
                Intra.defaultDNSAsFallback(false)
                val tunnel = Intra.connect(
                    tunReference.fd.toLong(),
                    linkMtu.toLong(),
                    mtu.toLong(),
                    TUN_IFADDRS,
                    FAKE_DNS,
                    defaultDns,
                    bridge,
                )
                createdTunnel = tunnel
                check(tunnel.isConnected()) { "Firestack returned a disconnected TUN stack" }
                return FirestackTunnelAdapter(tunReference, tunnel, bridge, linkMtu)
            } catch (error: Throwable) {
                runCatching { createdTunnel?.disconnect() }
                runCatching { bridge?.close() }
                runCatching { tunReference.close() }
                throw error
            }
        }

        private fun formatHostPort(addresses: String): String =
            addresses.split(',').map { address ->
                val value = address.trim()
                when {
                    value.isEmpty() -> error("DNS resolver address must not be empty")
                    value.startsWith("[") && value.contains("]:") -> value
                    value.contains(":") -> "[$value]:53"
                    else -> "$value:53"
                }
            }.joinToString(",")
    }
}

private class FirewallDNSFirestackBridge(
    private val vpnService: VpnService,
    private val engine: EngineRuntime,
    private val flowPolicyAdapter: AndroidFlowPolicyAdapter,
    private val physicalNetworkProvider: () -> Network?,
    private val isUidBlocked: (Int) -> Boolean,
    private val onDnsDecision: (String, Int, Int?, String, PolicyAction) -> Unit,
    private val onSocketProtectionResult: (Boolean) -> Unit,
    private val onSocketBindingResult: (Boolean) -> Unit,
    private val onFlowSnapshot: (FlowMonitorSnapshot) -> Unit,
) : Bridge, AutoCloseable {

    private val closed = AtomicBoolean(false)

    override fun bind4(who: String?, addrport: String?, fd: Long) = bindToPhysicalNetwork(fd)
    override fun bind6(who: String?, addrport: String?, fd: Long) = bindToPhysicalNetwork(fd)

    private fun bindToPhysicalNetwork(fd: Long) {
        if (closed.get()) return
        val descriptor = fd.toInt()
        // Firestack invokes Bind4/Bind6 instead of Protect for global-unicast
        // sockets, so this callback must perform both Android operations.
        protectSocket(descriptor)
        val network = physicalNetworkProvider() ?: run {
            runCatching { onSocketBindingResult(false) }
            return
        }
        val result = runCatching {
            ParcelFileDescriptor.fromFd(descriptor).use { duplicate ->
                network.bindSocket(duplicate.fileDescriptor)
            }
        }
        runCatching { onSocketBindingResult(result.isSuccess) }
        if (result.isFailure) {
            throw IllegalStateException("Unable to bind Firestack socket to the active physical network", result.exceptionOrNull())
        }
    }

    override fun protect(who: String?, fd: Long) {
        if (closed.get()) throw IllegalStateException("FirewallDNS Firestack bridge is closed")
        protectSocket(fd.toInt())
    }

    private fun protectSocket(descriptor: Int) {
        val protected = runCatching { vpnService.protect(descriptor) }.getOrDefault(false)
        runCatching { onSocketProtectionResult(protected) }
        if (!protected) throw IllegalStateException("VpnService.protect failed for Firestack socket $descriptor")
    }

    override fun preflow(protocol: Int, uid: Int, cid: String?, src: String?, dst: String?): PreMark =
        PreMark().apply {
            setUID(if (uid >= 0) uid.toString() else Intra.UNKNOWN_UID_STR)
            setIsUidSelf(false)
        }

    override fun flow(
        protocol: Int,
        uid: Int,
        cid: String?,
        src: String?,
        dst: String?,
        origdsts: String?,
        domains: String?,
        probableDomains: String?,
        blocklists: String?,
        dstIsAlg: Boolean,
    ): Mark {
        val appPackage = flowPolicyAdapter.resolvePackageForUid(uid)
        val domainAssessment = domains.orEmpty().split(',').map(String::trim).filter(String::isNotEmpty)
            .map { domain -> runCatching { engine.evaluateDomain(domain, appPackage) }.getOrNull() }
            .filterNotNull()
        val selectedDomainDecision = (domainAssessment.firstOrNull { it.action == PolicyAction.BLOCK }
            ?: domainAssessment.firstOrNull { it.action == PolicyAction.OBSERVE })?.let {
            NetworkFlowDecision(it.action, it.reason, it.ruleId, it.source, it.policyRevision)
        }
        val destination = parseFirestackEndpoint(dst.orEmpty(), portless = false)
        val encryptedDnsPort = destination?.let {
            EncryptedDnsGuard.shouldBlockPort(protocol, it.second)
        } == true
        val confirmedDoh = domains.orEmpty().split(',').map(String::trim)
            .any(EncryptedDnsGuard::isKnownDohEndpoint)
        val probableDoh = probableDomains.orEmpty().split(',').map(String::trim)
            .any(EncryptedDnsGuard::isKnownDohEndpoint)
        val encryptedDnsDecision = when {
            encryptedDnsPort -> NetworkFlowDecision(
                PolicyAction.BLOCK, "encrypted_dns_transport_blocked",
                "encrypted-dns-port-guard", RuleSource.MANAGED, engine.flowPolicyRevision,
            )
            confirmedDoh -> NetworkFlowDecision(
                PolicyAction.BLOCK, "known_doh_endpoint_blocked",
                "known-doh-endpoint-guard", RuleSource.MANAGED, engine.flowPolicyRevision,
            )
            probableDoh -> NetworkFlowDecision(
                PolicyAction.OBSERVE, "probable_doh_endpoint_observed",
                "probable-doh-endpoint-guard", RuleSource.HEURISTIC, engine.flowPolicyRevision,
            )
            else -> null
        }
        val effectiveDomainDecision = when {
            encryptedDnsDecision?.action == PolicyAction.BLOCK -> encryptedDnsDecision
            selectedDomainDecision?.action == PolicyAction.BLOCK -> selectedDomainDecision
            selectedDomainDecision?.action == PolicyAction.OBSERVE -> selectedDomainDecision
            else -> encryptedDnsDecision
        }
        val safeCid = cid.orEmpty()
        val decision = evaluateFlowCallback(protocol, uid, safeCid, src.orEmpty(), dst.orEmpty(), effectiveDomainDecision)
        runCatching { onFlowSnapshot(engine.flowMonitor.snapshot()) }
        return decisionMark(safeCid, uid, decision.action != PolicyAction.ALLOW && decision.action != PolicyAction.OBSERVE)
    }

    override fun inflow(protocol: Int, uid: Int, cid: String?, src: String?, dst: String?): Mark {
        val safeCid = cid.orEmpty()
        val decision = evaluateFlowCallback(protocol, uid, safeCid, src.orEmpty(), dst.orEmpty())
        runCatching { onFlowSnapshot(engine.flowMonitor.snapshot()) }
        return decisionMark(safeCid, uid, decision.action != PolicyAction.ALLOW && decision.action != PolicyAction.OBSERVE)
    }

    private fun evaluateFlowCallback(
        protocol: Int,
        uid: Int,
        cid: String,
        src: String,
        dst: String,
        domainDecision: NetworkFlowDecision? = null,
    ): NetworkFlowDecision = runCatching {
        val portless = protocol == 1 || protocol == 58
        val source = requireNotNull(parseFirestackEndpoint(src, portless)) { "Invalid Firestack source endpoint" }
        val destination = requireNotNull(parseFirestackEndpoint(dst, portless)) { "Invalid Firestack destination endpoint" }
        flowPolicyAdapter.evaluate(
            flowId = cid,
            protocolNumber = protocol,
            ownerUid = uid,
            sourceAddress = source.first,
            sourcePort = source.second,
            destinationAddress = destination.first,
            destinationPort = destination.second,
            domainDecision = domainDecision,
        )
    }.getOrElse {
        engine.flowMonitor.recordBlocked()
        NetworkFlowDecision(
            PolicyAction.BLOCK,
            "flow_policy_evaluation_failed",
            "flow-policy-evaluation-error",
            RuleSource.MANAGED,
            engine.flowPolicyRevision,
        )
    }

    private fun decisionMark(cid: String, uid: Int, blocked: Boolean): Mark =
        Mark().apply {
            setPIDCSV(if (blocked) Backend.Block else Backend.Base)
            setCID(cid)
            setUID(if (uid >= 0) uid.toString() else Intra.UNKNOWN_UID_STR)
        }

    override fun flowing(mark: Mark?) = Unit

    override fun postflow(summary: FlowSummary?) {
        val flowSummary = summary ?: return
        val id = flowSummary.getID()
        if (id.isBlank()) return
        flowPolicyAdapter.recordBytes(id, flowSummary.getTx().coerceAtLeast(0), flowSummary.getRx().coerceAtLeast(0))
        flowPolicyAdapter.close(id)
        runCatching { onFlowSnapshot(engine.flowMonitor.snapshot()) }
    }

    override fun onPrequery(who: String?, fid: String?, uid: String?, domain: String?, qtyp: Long): DomainOpts? = null

    override fun onQuery(who: String?, fid: String?, uid: String?, domain: String?, qtyp: Long): DNSOpts {
        val uidValue = uid.orEmpty()
        val domainValue = domain.orEmpty()
        val ownerUid = uidValue.toIntOrNull()
        val appPackage = ownerUid?.let(flowPolicyAdapter::resolvePackageForUid)
        val decision = runCatching { engine.evaluateDomain(domainValue, appPackage) }.getOrNull()
        val appBlocked = ownerUid?.takeIf { it >= 0 }?.let { runCatching { isUidBlocked(it) }.getOrDefault(false) } == true
        val action = when {
            appBlocked -> PolicyAction.BLOCK
            decision == null -> PolicyAction.BLOCK
            else -> decision.action
        }
        val reason = when {
            appBlocked -> "app_uid_blocked"
            decision == null -> "dns_policy_evaluation_failed"
            else -> decision.reason
        }
        runCatching { onDnsDecision(domainValue, qtyp.toInt(), ownerUid, reason, action) }
        return DNSOpts().apply {
            setUID(uidValue)
            setTIDCSV(if (action == PolicyAction.BLOCK) Backend.Block else Backend.Default)
        }
    }

    override fun onUpstreamAnswer(
        who: String?,
        fid: String?,
        summary: DNSSummary?,
        forPref: DNSOpts?,
        unmodifiedipcsv: String?,
    ): DNSOpts? = null

    override fun onResponse(summary: DNSSummary?) = Unit
    override fun onDNSAdded(id: String?) = Unit
    override fun onDNSRemoved(id: String?) = Unit
    override fun onDNSStopped() = Unit
    override fun onSvcComplete(summary: ServerSummary?) = Unit
    override fun svcRoute(cid: String?, src: String?, dst: String?, origdsts: String?, domains: String?): Tab =
        Tab().apply {
            setCID(cid.orEmpty())
            setBlock(false)
        }

    override fun onProxiesStopped() = Unit
    override fun onProxyAdded(id: String?, addr: String?) = Unit
    override fun onProxyRemoved(id: String?, addr: String?) = Unit
    override fun onProxyStopped(id: String?, addr: String?) = Unit
    override fun onProxyUpdated(id: String?, addr: String?) = Unit

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
    }

}

internal fun parseFirestackEndpoint(value: String, portless: Boolean): Pair<String, Int>? = runCatching {
    val endpoint = value.trim()
    require(endpoint.isNotEmpty())
    if (portless) {
        val host = when {
            endpoint.startsWith("[") && endpoint.contains("]") ->
                endpoint.substring(1, endpoint.indexOf(']'))
            endpoint.count { it == ':' } == 1 -> endpoint.substringBeforeLast(':')
            else -> endpoint
        }
        require(host.isNotBlank())
        host to 0
    } else {
        val host: String
        val portText: String
        if (endpoint.startsWith("[")) {
            val close = endpoint.indexOf(']')
            require(close > 1 && endpoint.getOrNull(close + 1) == ':')
            host = endpoint.substring(1, close)
            portText = endpoint.substring(close + 2)
        } else {
            val separator = endpoint.lastIndexOf(':')
            require(separator > 0)
            host = endpoint.substring(0, separator)
            portText = endpoint.substring(separator + 1)
        }
        val port = portText.toIntOrNull() ?: throw IllegalArgumentException("Invalid port")
        require(port in 1..65535)
        host to port
    }
}.getOrNull()
