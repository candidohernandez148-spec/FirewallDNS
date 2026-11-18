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
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Puente Firestack del servicio [FirewallVpnService]:
 * protege sockets, bloquea dominios con [DomainBlocker] y conexiones por app con [AppFirewallManager].
 */
class FirestackBridge(
    private val vpn: VpnService,
    private val context: Context = vpn.applicationContext
) : Bridge {

    // Backend.Default resuelve con los DNS de la red física activa (DNS53).
    @Volatile
    var upstreamId: String = Backend.Default

    private val appLabels = ConcurrentHashMap<Int, String>()
    private val pendingAppLabels = ConcurrentHashMap.newKeySet<Int>()
    private val labelScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val recentConnections = ConcurrentHashMap<String, Long>()
    private val lastEvaluationFailureLog = AtomicLong(0L)

    private companion object {
        const val CONNECTION_DEDUP_MS = 4000L
        const val EVALUATION_ERROR_LOG_INTERVAL_MS = 10_000L
        val VPN_DNS = setOf("10.111.222.3", "fd66:f83a:c650::3")
        val SINKHOLE_IPS = setOf("0.0.0.0", "::", "::0")
    }

    override fun bind4(who: String?, addrPort: String?, fd: Long) = protect(who, fd)

    override fun bind6(who: String?, addrPort: String?, fd: Long) = protect(who, fd)

    override fun protect(who: String?, fd: Long) {
        vpn.protect(fd.toInt())
    }

    // BlockAll hace que Firestack responda de inmediato sin consultar al DNS de la red.
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
        val numericUid = uid?.toIntOrNull()
        val appName = if (numericUid != null && numericUid >= 0) appLabel(numericUid) else "Sistema / DNS"
        FirewallRepository.addLog(
            domain = qname,
            qType = when (qtype) {
                1L -> "A"
                28L -> "AAAA"
                65L -> "HTTPS"
                5L -> "CNAME"
                16L -> "TXT"
                else -> "T$qtype"
            },
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

    // Nueva conexión TCP/UDP: se descarta (Block) si la app propietaria o el dominio están bloqueados.
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

        // Evita ruido de conexiones hacia la IP nula cuando un dominio fue bloqueado por DNS.
        if (target != null && target.first in SINKHOLE_IPS) {
            mark.pidcsv = Backend.Block
            return mark
        }

        val isDns = target != null && (target.second == 53 || target.first in VPN_DNS)
        if (isDns) {
            mark.pidcsv = Backend.Base
            return mark
        }

        val appBlocked = owner >= 0 && AppFirewallManager.isUidBlocked(owner)
        val exactDomains = domains.orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }
        val probableList = probableDomains.orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }

        val blockedName = if (appBlocked) null else exactDomains.firstOrNull { evaluate(it).first }
        val blocked = appBlocked || blockedName != null
        mark.pidcsv = if (blocked) Backend.Block else Backend.Exit

        val displayLabel = exactDomains.firstOrNull()
            ?: probableList.firstOrNull()
            ?: target?.first
            ?: dst.orEmpty()

        val reason = when {
            appBlocked -> "Internet bloqueado para la app"
            blockedName != null -> "Dominio bloqueado"
            else -> "Conexión permitida"
        }

        logConnection(owner, protocol, target, displayLabel, blocked, reason)
        return mark
    }

    /**
     * Mantiene la política fail-open para evitar cortar toda la conectividad ante
     * un fallo interno, pero deja constancia visible del error en el historial.
     */
    private fun evaluate(domain: String): Pair<Boolean, String> = try {
        val normalized = DomainBlocker.normalize(domain)
        if (normalized.isBlank()) {
            false to "Dominio no válido"
        } else {
            FirewallRepository.evaluateDomain(normalized)
        }
    } catch (error: Exception) {
        val now = System.currentTimeMillis()
        val previous = lastEvaluationFailureLog.get()
        if (now - previous >= EVALUATION_ERROR_LOG_INTERVAL_MS &&
            lastEvaluationFailureLog.compareAndSet(previous, now)
        ) {
            try {
                FirewallRepository.addLog(
                    domain = domain.take(253),
                    qType = "ERROR",
                    isBlocked = false,
                    reason = "Error al evaluar reglas; permitido por compatibilidad (${error.javaClass.simpleName})",
                    appName = "FirewallDNS"
                )
            } catch (_: Exception) {
                // El registro nunca debe interrumpir el callback de Firestack.
            }
        }
        false to "Error al evaluar reglas; permitido por compatibilidad"
    }

    private fun logConnection(
        uid: Int, protocol: Int, target: Pair<String, Int>?, label: String, blocked: Boolean, reason: String
    ) {
        val key = "$uid|$label|${target?.second}|$blocked"
        val now = System.currentTimeMillis()
        val last = recentConnections[key]
        if (last != null && now - last < CONNECTION_DEDUP_MS) return
        if (recentConnections.size > 500) {
            recentConnections.entries.removeIf { now - it.value > CONNECTION_DEDUP_MS }
            if (recentConnections.size > 1500) recentConnections.clear()
        }
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

    // No consultar PackageManager dentro de callbacks DNS/flow: puede implicar I/O y bloquear Firestack.
    // La primera entrada muestra el UID; las siguientes usan la etiqueta ya resuelta en Dispatchers.IO.
    private fun appLabel(uid: Int): String {
        if (uid == 0) return "Sistema (root)"
        if (uid == Process.SYSTEM_UID) return "Sistema Android"
        appLabels[uid]?.let { return it }
        if (pendingAppLabels.add(uid)) {
            labelScope.launch {
                try {
                    val pm = vpn.packageManager
                    val pkg = pm.getPackagesForUid(uid)?.firstOrNull()
                    val label = if (pkg != null) {
                        pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
                    } else {
                        "UID $uid"
                    }
                    appLabels.putIfAbsent(uid, label)
                } catch (_: Exception) {
                    appLabels.putIfAbsent(uid, "UID $uid")
                } finally {
                    pendingAppLabels.remove(uid)
                }
            }
        }
        return "UID $uid"
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
