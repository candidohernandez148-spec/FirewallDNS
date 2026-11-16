package com.firewall.dns.service

import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Process
import android.system.OsConstants
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
import com.firewall.dns.domain.engine.NgfwRuleEngine
import java.net.InetAddress
import java.net.InetSocketAddress
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
    ): Mark = decide(protocol, uid, src, dst, realIps, domains ?: probableDomains)

    // El tráfico entrante pertenece a conexiones ya aceptadas en flow(); no se vuelve a filtrar.
    override fun inflow(protocol: Int, uid: Int, src: String?, dst: String?): Mark {
        val mark = Mark()
        mark.cid = UUID.randomUUID().toString().take(8)
        mark.pidcsv = Backend.Exit
        mark.uid = uid.toString()
        return mark
    }

    private fun decide(
        protocol: Int, rawUid: Int, src: String?, dst: String?, realIps: String?, domains: String? = null
    ): Mark {
        val mark = Mark()
        mark.cid = UUID.randomUUID().toString().take(8)
        mark.pidcsv = Backend.Exit

        val target = NgfwRuleEngine.splitHostPort(dst)
        // Sin políticas no hay nada que evaluar: camino rápido, solo se cuenta.
        if (!FirewallRepository.hasNgfwPolicies()) {
            mark.uid = rawUid.toString()
            if (target != null && (target.second == 53 || target.first in VPN_DNS)) {
                mark.pidcsv = Backend.Base
            } else if (target != null) {
                val uid = if (rawUid >= 0) rawUid else lookupUid(protocol, src, dst)
                logAllowed(uid, protocol, target, domains)
            }
            return mark
        }
        val uid = if (rawUid >= 0) rawUid else lookupUid(protocol, src, dst)
        mark.uid = uid.toString()
        if (target == null) return mark

        // El DNS lo resuelve Firestack y se filtra en onQuery; nunca pasa por las políticas.
        if (target.second == 53 || target.first in VPN_DNS) {
            mark.pidcsv = Backend.Base
            return mark
        }

        // Si Firestack ya resolvió la IP real tras ALG, se evalúa esa en lugar de la virtual.
        val destIp = realIps?.split(',')?.map { it.trim() }
            ?.firstOrNull { NgfwRuleEngine.parseIp(it)?.any { b -> b.toInt() != 0 } == true }
            ?: target.first

        val (packages, label) = if (uid > 0) appFor(uid) else (emptyList<String>() to "Sistema")
        val reason = try {
            FirewallRepository.evaluateFlow(packages, protocol, destIp, target.second)
        } catch (_: Throwable) {
            null
        }
        if (reason != null) {
            mark.pidcsv = Backend.Block
            FirewallRepository.addLog(
                domain = "$destIp:${target.second}",
                qType = protoName(protocol),
                isBlocked = true,
                reason = reason,
                appName = label
            )
        }
        else logAllowed(uid, protocol, target, domains)
        return mark
    }

    private val recentAllowed = HashMap<String, Long>()

    // Registra la conexión permitida; evita repetir la misma app/destino durante 3 s.
    private fun logAllowed(uid: Int, protocol: Int, target: Pair<String, Int>, domains: String?) {
        val name = domains?.split(',')?.firstOrNull { it.isNotBlank() }?.trim()?.trimEnd('.')
        val host = name ?: "${target.first}:${target.second}"
        val label = if (uid > 0) appFor(uid).second else "Sistema"
        val key = "$uid|$host"
        val now = System.currentTimeMillis()
        synchronized(recentAllowed) {
            val last = recentAllowed[key]
            if (last != null && now - last < 3000) return
            if (recentAllowed.size > 500) recentAllowed.clear()
            recentAllowed[key] = now
        }
        FirewallRepository.addLog(
            domain = host,
            qType = protoName(protocol),
            isBlocked = false,
            reason = "Permitido",
            appName = label
        )
    }

    private fun lookupUid(protocol: Int, src: String?, dst: String?): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return Process.INVALID_UID
        val s = NgfwRuleEngine.splitHostPort(src) ?: return Process.INVALID_UID
        val d = NgfwRuleEngine.splitHostPort(dst) ?: return Process.INVALID_UID
        val proto = when (protocol) {
            6 -> OsConstants.IPPROTO_TCP
            17 -> OsConstants.IPPROTO_UDP
            else -> return Process.INVALID_UID
        }
        return try {
            connectivityManager.getConnectionOwnerUid(
                proto,
                InetSocketAddress(InetAddress.getByName(s.first), s.second),
                InetSocketAddress(InetAddress.getByName(d.first), d.second)
            )
        } catch (_: Exception) {
            Process.INVALID_UID
        }
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

    private fun protoName(protocol: Int) = when (protocol) {
        6 -> "TCP"
        17 -> "UDP"
        1 -> "ICMP"
        else -> "IP$protocol"
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
