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

    /** Transporte DoH registrado en el túnel; los dominios permitidos se resuelven por aquí. */
    @Volatile
    var upstreamId: String = Backend.Default

    private val appLabels = HashMap<Int, String>()

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
        val blocked = DomainBlocker.isBlocked(qname)
        opts.tidcsv = if (blocked) Backend.BlockAll else upstreamId
        FirewallRepository.addLog(
            domain = qname,
            qType = when (qtype) {
                1L -> "A"
                28L -> "AAAA"
                else -> "T$qtype"
            },
            isBlocked = blocked,
            reason = if (blocked) "Dominio bloqueado (NXDOMAIN)" else "Permitido",
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
        mark.pidcsv = if (owner != Process.INVALID_UID && AppFirewallManager.isUidBlocked(owner)) {
            Backend.Block
        } else {
            Backend.Exit
        }
        return mark
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
