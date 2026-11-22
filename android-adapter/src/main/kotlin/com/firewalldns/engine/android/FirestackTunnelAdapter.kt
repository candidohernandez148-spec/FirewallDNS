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
import com.firewalldns.engine.runtime.EngineRuntime
import java.net.URI
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns the Firestack/gVisor user-space network stack attached to the existing
 * Android VpnService TUN. It never creates a second VPN or reads the TUN fd.
 */
class FirestackTunnelAdapter private constructor(
    private val vpnService: VpnService,
    private val tunReference: ParcelFileDescriptor,
    private val tunnel: Tunnel,
    private val bridge: FirewallDNSFirestackBridge,
    private val defaultDnsAddress: String,
) : AutoCloseable {

    private val closed = AtomicBoolean(false)

    fun updatePhysicalNetworkResolver(resolver: String): Boolean {
        if (closed.get()) return false
        val address = formatHostPort(resolver)
        return runCatching {
            Intra.addDefaultTransport(tunnel, Backend.DNS53, address, "")
            true
        }.getOrDefault(false)
    }

    fun isConnected(): Boolean = !closed.get() && runCatching { tunnel.isConnected }.getOrDefault(false)

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
            resolver: String,
            engine: EngineRuntime,
            flowPolicyAdapter: AndroidFlowPolicyAdapter,
            physicalNetworkProvider: () -> Network?,
            resolvePackage: (Int) -> String?,
            isUidBlocked: (Int) -> Boolean = { false },
            onDnsDecision: (String, Int, Int?, String, PolicyAction) -> Unit = { _, _, _, _, _ -> },
            onSocketProtectionResult: (Boolean) -> Unit = {},
        ): FirestackTunnelAdapter {
            require(mtu in 576..9000) { "Invalid TUN MTU" }
            val tunReference = ParcelFileDescriptor.dup(tunDescriptor.fileDescriptor)
            var bridge: FirewallDNSFirestackBridge? = null
            var createdTunnel: Tunnel? = null
            try {
                bridge = FirewallDNSFirestackBridge(
                    vpnService = vpnService,
                    engine = engine,
                    flowPolicyAdapter = flowPolicyAdapter,
                    physicalNetworkProvider = physicalNetworkProvider,
                    resolvePackage = resolvePackage,
                    isUidBlocked = isUidBlocked,
                    onDnsDecision = onDnsDecision,
                    onSocketProtectionResult = onSocketProtectionResult,
                )
                val defaultDns = Intra.newDefaultDNS(
                    Backend.DNS53,
                    formatHostPort(resolver),
                    "",
                )
                Intra.defaultDNSAsFallback(false)
                val tunnel = Intra.connect(
                    tunReference.fd.toLong(),
                    mtu.toLong(),
                    mtu.toLong(),
                    TUN_IFADDRS,
                    FAKE_DNS,
                    defaultDns,
                    bridge,
                )
                createdTunnel = tunnel
                check(tunnel.isConnected) { "Firestack returned a disconnected TUN stack" }
                return FirestackTunnelAdapter(
                    vpnService,
                    tunReference,
                    tunnel,
                    bridge,
                    formatHostPort(resolver),
                )
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
    private val resolvePackage: (Int) -> String?,
    private val isUidBlocked: (Int) -> Boolean,
    private val onDnsDecision: (String, Int, Int?, String, PolicyAction) -> Unit,
    private val onSocketProtectionResult: (Boolean) -> Unit,
) : Bridge, AutoCloseable {

    private val boundNetworks = ConcurrentHashMap<Int, Network>()
    private val closed = AtomicBoolean(false)

    override fun bind4(who: String, addrport: String, fd: Long) = bindToPhysicalNetwork(fd)
    override fun bind6(who: String, addrport: String, fd: Long) = bindToPhysicalNetwork(fd)

    private fun bindToPhysicalNetwork(fd: Long) {
        if (closed.get()) return
        val descriptor = fd.toInt()
        val network = physicalNetworkProvider() ?: return
        val result = runCatching {
            ParcelFileDescriptor.fromFd(descriptor).use { duplicate ->
                network.bindSocket(duplicate.fileDescriptor)
            }
        }
        if (result.isSuccess) boundNetworks[descriptor] = network
        else throw IllegalStateException("Unable to bind Firestack socket to physical network", result.exceptionOrNull())
    }

    override fun protect(who: String, fd: Long) {
        if (closed.get()) throw IllegalStateException("FirewallDNS Firestack bridge is closed")
        val descriptor = fd.toInt()
        boundNetworks.remove(descriptor)
        val protected = vpnService.protect(descriptor)
        runCatching { onSocketProtectionResult(protected) }
        if (!protected) throw IllegalStateException("VpnService.protect failed for Firestack socket")
    }

    override fun preflow(protocol: Int, uid: Int, cid: String, src: String, dst: String): PreMark =
        PreMark().apply {
            setUID(if (uid >= 0) uid.toString() else Intra.UNKNOWN_UID_STR)
            setIsUidSelf(false)
        }

    override fun flow(
        protocol: Int,
        uid: Int,
        cid: String,
        src: String,
        dst: String,
        origdsts: String,
        domains: String,
        probableDomains: String,
        blocklists: String,
        dstIsAlg: Boolean,
    ): Mark {
        val appPackage = uid.takeIf { it >= 0 }?.let { runCatching { resolvePackage(it) }.getOrNull() }
        val domainAssessment = domains.split(',').map(String::trim).filter(String::isNotEmpty)
            .map { domain -> runCatching { engine.evaluateDomain(domain, appPackage) }.getOrNull() }
            .filterNotNull()
        val selectedDomainDecision = (domainAssessment.firstOrNull { it.action == PolicyAction.BLOCK }
            ?: domainAssessment.firstOrNull { it.action == PolicyAction.OBSERVE })?.let {
            NetworkFlowDecision(it.action, it.reason, it.ruleId, it.source, it.policyRevision)
        }
        val decision = evaluateFlowCallback(protocol, uid, cid, src, dst, selectedDomainDecision)
        return decisionMark(cid, uid, decision?.action != PolicyAction.ALLOW && decision?.action != PolicyAction.OBSERVE)
    }

    override fun inflow(protocol: Int, uid: Int, cid: String, src: String, dst: String): Mark {
        val decision = evaluateFlowCallback(protocol, uid, cid, src, dst)
        return decisionMark(cid, uid, decision?.action != PolicyAction.ALLOW && decision?.action != PolicyAction.OBSERVE)
    }

    private fun evaluateFlowCallback(
        protocol: Int,
        uid: Int,
        cid: String,
        src: String,
        dst: String,
        domainDecision: NetworkFlowDecision? = null,
    ) = runCatching {
        val portless = protocol == 1 || protocol == 58
        val source = parseEndpoint(src, portless) ?: return null
        val destination = parseEndpoint(dst, portless) ?: return null
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
    }.getOrNull()

    private fun decisionMark(cid: String, uid: Int, blocked: Boolean): Mark =
        Mark().apply {
            setPIDCSV(if (blocked) Backend.Block else Backend.Base)
            setCID(cid)
            setUID(if (uid >= 0) uid.toString() else Intra.UNKNOWN_UID_STR)
        }

    override fun flowing(mark: Mark) = Unit

    override fun postflow(summary: FlowSummary) {
        val id = summary.getID()
        if (id.isBlank()) return
        flowPolicyAdapter.recordBytes(id, summary.getTx().coerceAtLeast(0), summary.getRx().coerceAtLeast(0))
        flowPolicyAdapter.close(id)
    }

    override fun onPrequery(who: String, fid: String, uid: String, domain: String, qtyp: Long): DomainOpts? = null

    override fun onQuery(who: String, fid: String, uid: String, domain: String, qtyp: Long): DNSOpts {
        val ownerUid = uid.toIntOrNull()
        val appPackage = ownerUid?.takeIf { it >= 0 }?.let { runCatching { resolvePackage(it) }.getOrNull() }
        val decision = engine.evaluateDomain(domain, appPackage)
        val appBlocked = ownerUid?.takeIf { it >= 0 }?.let { runCatching { isUidBlocked(it) }.getOrDefault(false) } == true
        val action = if (appBlocked) PolicyAction.BLOCK else decision.action
        val reason = if (appBlocked) "app_uid_blocked" else decision.reason
        runCatching { onDnsDecision(domain, qtyp.toInt(), ownerUid, reason, action) }
        return DNSOpts().apply {
            setUID(uid)
            setTIDCSV(if (action == PolicyAction.BLOCK) Backend.Block else Backend.Default)
        }
    }

    override fun onUpstreamAnswer(
        who: String,
        fid: String,
        summary: DNSSummary,
        forPref: DNSOpts,
        unmodifiedipcsv: String,
    ): DNSOpts? = null

    override fun onResponse(summary: DNSSummary) = Unit
    override fun onDNSAdded(id: String) = Unit
    override fun onDNSRemoved(id: String) = Unit
    override fun onDNSStopped() = Unit
    override fun onSvcComplete(summary: ServerSummary) = Unit
    override fun svcRoute(cid: String, src: String, dst: String, origdsts: String, domains: String): Tab =
        Tab().apply {
            setCID(cid)
            setBlock(false)
        }

    override fun onProxiesStopped() = Unit
    override fun onProxyAdded(id: String, addr: String) = Unit
    override fun onProxyRemoved(id: String, addr: String) = Unit
    override fun onProxyStopped(id: String, addr: String) = Unit
    override fun onProxyUpdated(id: String, addr: String) = Unit

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        boundNetworks.clear()
    }

    private fun parseEndpoint(value: String, portless: Boolean): Pair<String, Int>? = runCatching {
        if (portless) {
            val host = when {
                value.startsWith("[") && value.contains("]:") -> value.substring(1, value.indexOf("]:"))
                value.startsWith("[") && value.endsWith("]") -> value.substring(1, value.length - 1)
                value.contains(":") && value.count { it == ':' } == 1 -> value.substringBefore(':')
                else -> value
            }
            require(host.isNotBlank())
            host to 0
        } else {
            val uri = URI("tcp://$value")
            val host = uri.host ?: return null
            val port = uri.port
            require(port in 1..65535)
            host.removePrefix("[").removeSuffix("]") to port
        }
    }.getOrNull()
}
