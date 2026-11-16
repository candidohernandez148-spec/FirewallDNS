package com.firewall.dns.service

import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Process
import com.celzero.firestack.backend.Backend
import com.celzero.firestack.backend.DNSOpts
import com.celzero.firestack.backend.DNSSummary
import com.celzero.firestack.backend.ServerSummary
import com.celzero.firestack.backend.Tab
import com.celzero.firestack.intra.Bridge
import com.celzero.firestack.intra.FlowSummary
import com.celzero.firestack.intra.Mark
import com.celzero.firestack.intra.PreMark
import com.firewall.dns.data.repository.FirewallRepository
import java.util.UUID

/** Puente entre Firestack y las reglas NGFW (app, IP, puerto, protocolo) y de dominio. */
class NgfwBridge(
    private val vpn: VpnService,
    private val connectivityManager: ConnectivityManager
) : Bridge {

    /** Id del transporte DNS ascendente registrado en el túnel. */
    @Volatile
    var upstreamId: String = Backend.Default

    private companion object {
        val VPN_DNS = setOf("10.10.10.1", "fd00:10:10::1")
    }

    private val appLabels = HashMap<Int, Pair<List<String>, String>>()

    override fun bind4(who: String?, addrPort: String?, fd: Long) = protect(who, fd)

    override fun bind6(who: String?, addrPort: String?, fd: Long) = protect(who, fd)

    override fun protect(who: String?, fd: Long) {
        vpn.protect(fd.toInt())
    }

    override fun onQuery(origin: String?, uid: String?, fqdn: String?, qtype: Long): DNSOpts {
        val opts = DNSOpts()
        opts.uid = uid ?: ""
        opts.ipcsv = ""
        val domain = fqdn?.trim()?.trimEnd('.')?.lowercase().orEmpty()
        if (domain.isEmpty()) {
            opts.tidcsv = upstreamId
            return opts
        }
        val (blocked, reason) = try {
            FirewallRepository.evaluateDomain(domain)
        } catch (_: Throwable) {
            false to "Permitido"
        }
        opts.tidcsv = if (blocked) Backend.BlockAll else upstreamId
        val appName = uid?.toIntOrNull()?.let { appFor(it).second } ?: "Sistema / DNS"
        FirewallRepository.addLog(
            domain = domain,
            qType = if (qtype == 28L) "AAAA" else if (qtype == 1L) "A" else "T$qtype",
            isBlocked = blocked,
            reason = reason,
            appName = appName
        )
        return opts
    }

    override fun onUpstreamAnswer(
        origin: String?, summary: DNSSummary?, opts: DNSOpts?, uid: String?
    ): DNSOpts = opts ?: DNSOpts()

    override fun preflow(protocol: Int, uid: Int, src: String?, dst: String?): PreMark {
        val pre = PreMark()
        pre.uid = uid.toString()
        pre.isUidSelf = uid == Process.myUid()
        return pre
    }

    override fun flow(
        protocol: Int,
        uid: Int,
        src: String?,
        dst: String?,
        realIps: String?,
        domains: String?,
        probableDomains: String?,
        blocklists: String?,
        isAlg: Boolean
    ): Mark = decide(uid, dst)

    // El tráfico entrante pertenece a conexiones ya aceptadas en flow(); no se vuelve a filtrar.
    override fun inflow(protocol: Int, uid: Int, src: String?, dst: String?): Mark {
        val mark = Mark()
        mark.cid = UUID.randomUUID().toString().take(8)
        mark.pidcsv = Backend.Exit
        mark.uid = uid.toString()
        return mark
    }

    private fun splitHostPort(value: String?): Pair<String, Int>? {
        if (value.isNullOrEmpty()) return null
        val idx = value.lastIndexOf(':')
        if (idx <= 0) return null
        val port = value.substring(idx + 1).toIntOrNull() ?: return null
        return value.substring(0, idx).removePrefix("[").removeSuffix("]") to port
    }

    private fun decide(
        rawUid: Int, dst: String?
    ): Mark {
        val mark = Mark()
        mark.cid = UUID.randomUUID().toString().take(8)
        mark.pidcsv = Backend.Exit

        val target = splitHostPort(dst)
        // NGFW solo filtra DNS (onQuery); las conexiones pasan sin evaluarse ni registrarse.
        mark.uid = rawUid.toString()
        if (target != null && (target.second == 53 || target.first in VPN_DNS)) {
            mark.pidcsv = Backend.Base
        }
        return mark
    }

    @Synchronized
    private fun appFor(uid: Int): Pair<List<String>, String> = appLabels.getOrPut(uid) {
        try {
            val pm = vpn.packageManager
            val pkgs = pm.getPackagesForUid(uid)?.toList().orEmpty()
            val label = pkgs.firstOrNull()?.let {
                pm.getApplicationLabel(pm.getApplicationInfo(it, 0)).toString()
            } ?: "UID $uid"
            pkgs to label
        } catch (_: Exception) {
            emptyList<String>() to "UID $uid"
        }
    }

    override fun flowing(m: Mark?) {}

    override fun postflow(summary: FlowSummary?) {}

    override fun svcRoute(a: String?, b: String?, c: String?, d: String?, e: String?): Tab = Tab()

    override fun onSvcComplete(summary: ServerSummary?) {}

    override fun onResponse(summary: DNSSummary?) {}

    override fun onDNSAdded(id: String?) {}

    override fun onDNSRemoved(id: String?) {}

    override fun onDNSStopped() {}

    override fun onProxiesStopped() {}

    override fun onProxyAdded(id: String?, handle: String?) {}

    override fun onProxyRemoved(id: String?, handle: String?) {}

    override fun onProxyStopped(id: String?, handle: String?) {}

    override fun onProxyUpdated(id: String?, handle: String?) {}
}
