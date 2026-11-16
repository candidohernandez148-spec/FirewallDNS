package com.firewall.dns.service

import android.content.Context
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
import com.firewall.dns.domain.engine.AppFirewallManager
import com.firewall.dns.domain.engine.DomainBlocker
import java.util.UUID

/**
 * Puente Firestack del servicio [FirewallVpnService]:
 * protege sockets, bloquea dominios con [DomainBlocker] y conexiones por app con [AppFirewallManager].
 */
class FirestackBridge(
    private val vpn: VpnService,
    private val context: Context = vpn.applicationContext
) : Bridge {

    /** Transportes DoH registrados en Firestack; el proveedor elegido se lee en cada consulta. */
    @Volatile
    var registeredTransports: Set<String> = emptySet()

    private val upstreamId: String
        get() = FirewallRepository.dnsProvider().transportId.takeIf { it in registeredTransports } ?: Backend.Preferred

    private val appLabels = HashMap<Int, String>()
    private val recentConnections = java.util.concurrent.ConcurrentHashMap<String, Long>()

    private companion object {
        const val CONNECTION_DEDUP_MS = 4000L
        val VPN_DNS = setOf("10.111.222.3", "fd66:f83a:c650::3")
    }

    override fun bind4(who: String?, addrPort: String?, fd: Long) = protect(who, fd)

    override fun bind6(who: String?, addrPort: String?, fd: Long) = protect(who, fd)

    override fun protect(who: String?, fd: Long) {
        vpn.protect(fd.toInt())
    }

    // BlockAll hace que Firestack responda de inmediato sin consultar al servidor DoH.
    override fun onQuery(origin: String?, uid: String?, fqdn: String?, qtype: Long): DNSOpts {
        val opts = DNSOpts()
        opts.uid = uid ?: ""
        opts.ipcsv = ""
        val qname = DomainBlocker.normalize(fqdn.orEmpty())
        if (qname.isEmpty()) {
            opts.tidcsv = upstreamId
            return opts
        }
        val (blocked, reason) = evaluate(qname)
        opts.tidcsv = if (blocked) Backend.BlockAll else upstreamId
        FirewallRepository.addLog(
            domain = qname,
            qType = when (qtype) {
                1L -> "A"
                28L -> "AAAA"
                else -> "T$qtype"
            },
            isBlocked = blocked,
            reason = reason,
            appName = uid?.toIntOrNull()?.let { appLabel(it) } ?: "Sistema / DNS"
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

    // Nueva conexión TCP/UDP: se descarta (Block) si la app propietaria está bloqueada.
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
    ): Mark {
        val mark = Mark()
        mark.cid = UUID.randomUUID().toString().take(8)
        val owner = resolveUid(protocol, uid, src, dst)
        mark.uid = owner.toString()
        val target = splitHostPort(dst)
        val isDns = target != null && (target.second == 53 || target.first in VPN_DNS)
        if (isDns) {
            mark.pidcsv = Backend.Base
            return mark
        }
        val appBlocked = owner != Process.INVALID_UID && AppFirewallManager.isUidBlocked(owner)
        val names = domains.orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }
        val blockedName = if (appBlocked) null else names.firstOrNull { evaluate(it).first }
        val blocked = appBlocked || blockedName != null
        mark.pidcsv = if (blocked) Backend.Block else Backend.Exit
        logConnection(
            owner, protocol, target, names.firstOrNull() ?: target?.first ?: dst.orEmpty(),
            blocked, if (appBlocked) "Internet bloqueado para la app" else if (blockedName != null) "Dominio bloqueado" else "Conexión permitida"
        )
        return mark
    }

    private fun evaluate(domain: String): Pair<Boolean, String> = try {
        FirewallRepository.evaluateDomain(DomainBlocker.normalize(domain))
    } catch (_: Throwable) {
        false to "Permitido"
    }

    // Registra conexiones de cada app; se evita repetir la misma app y destino en una ventana corta.
    private fun logConnection(
        uid: Int, protocol: Int, target: Pair<String, Int>?, label: String, blocked: Boolean, reason: String
    ) {
        val key = "$uid|$label|${target?.second}|$blocked"
        val now = System.currentTimeMillis()
        val last = recentConnections[key]
        if (last != null && now - last < CONNECTION_DEDUP_MS) return
        if (recentConnections.size > 500) recentConnections.entries.removeIf { now - it.value > CONNECTION_DEDUP_MS }
        recentConnections[key] = now
        FirewallRepository.addLog(
            domain = label,
            qType = (if (protocol == 17) "UDP" else "TCP") + (target?.let { ":${it.second}" } ?: ""),
            isBlocked = blocked,
            reason = reason,
            appName = if (uid >= 0) appLabel(uid) else "Sistema"
        )
    }

    override fun inflow(protocol: Int, uid: Int, src: String?, dst: String?): Mark {
        val mark = Mark()
        mark.cid = UUID.randomUUID().toString().take(8)
        mark.uid = uid.toString()
        mark.pidcsv = Backend.Exit
        return mark
    }

    // Si Firestack no conoce el uid, se consulta ConnectivityManager.getConnectionOwnerUid.
    private fun resolveUid(protocol: Int, uid: Int, src: String?, dst: String?): Int {
        if (uid >= 0) return uid
        val s = splitHostPort(src) ?: return Process.INVALID_UID
        val d = splitHostPort(dst) ?: return Process.INVALID_UID
        return AppFirewallManager.getUidForConnection(context, protocol, s.first, s.second, d.first, d.second)
    }

    private fun splitHostPort(value: String?): Pair<String, Int>? {
        if (value.isNullOrEmpty()) return null
        val idx = value.lastIndexOf(':')
        if (idx <= 0) return null
        val port = value.substring(idx + 1).toIntOrNull() ?: return null
        return value.substring(0, idx).removePrefix("[").removeSuffix("]") to port
    }

    @Synchronized
    private fun appLabel(uid: Int): String = appLabels.getOrPut(uid) {
        try {
            val pm = vpn.packageManager
            val pkg = pm.getPackagesForUid(uid)?.firstOrNull()
            if (pkg != null) pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() else "UID $uid"
        } catch (_: Exception) {
            "UID $uid"
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
