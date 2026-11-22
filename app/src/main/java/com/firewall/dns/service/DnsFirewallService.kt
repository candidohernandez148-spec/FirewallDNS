package com.firewall.dns.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.Process
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.firewall.dns.MainActivity
import com.firewall.dns.R
import com.firewall.dns.data.repository.FirewallRepository
import com.firewall.dns.domain.engine.AppFirewallManager
import com.firewall.dns.domain.engine.DnsPacketEngine
import com.firewalldns.engine.android.AndroidEngineRuntime
import com.firewalldns.engine.android.AndroidFlowPolicyAdapter
import com.firewalldns.engine.android.FirestackTunnelAdapter
import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.dns.DnsExchangeCancellation
import com.firewalldns.engine.dns.DnsUpstreamConfig
import com.firewalldns.engine.dns.DnsUpstreamFailoverClient
import com.firewalldns.engine.dns.DnsUpstreamResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class DnsFirewallService : VpnService() {

    private class TunSession(
        val descriptor: ParcelFileDescriptor,
        val firestack: FirestackTunnelAdapter,
    ) {
        val active = AtomicBoolean(true)
    }

    @Volatile
    private var activeTunSession: TunSession? = null
    private val vpnLock = Any()
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Volatile
    private var isRunning = false

    private val uidAppCache = ConcurrentHashMap<Int, String>()

    private lateinit var connectivityManager: ConnectivityManager
    @Volatile private var sharedEngine: AndroidEngineRuntime? = null
    @Volatile private var sharedFlowPolicyAdapter: AndroidFlowPolicyAdapter? = null
    private val physicalNetworkGeneration = AtomicLong(0L)
    private val upstreamConfigGeneration = AtomicLong(0L)
    private val firestackResolverGeneration = AtomicLong(-1L)
    private data class UpstreamSnapshot(
        val client: DnsUpstreamFailoverClient,
        val resolvers: List<String>,
        val physicalNetwork: android.net.Network?,
        val linkMtu: Int,
    )
    /**
     * Client and resolver labels are one immutable publication. Keeping them
     * together prevents diagnostics from labelling attempts with a newer network.
     */
    @Volatile private var upstreamSnapshot: UpstreamSnapshot? = null
    @Volatile private var selectedPhysicalNetwork: android.net.Network? = null
    @Volatile private var physicalNetworkCallback: ConnectivityManager.NetworkCallback? = null
    private val upstreamRefreshLock = Any()
    private val networkHandoverRecoveryScheduled = AtomicBoolean(false)

    companion object {
        @Volatile private var diagnosticInstance: DnsFirewallService? = null

        /**
         * Runs the forced upstream TCP diagnostic from the in-app diagnostics screen
         * or the legacy signature-protected provider. Call from an I/O thread, never
         * from the TUN packet loop.
         */
        fun runDiagnosticTcpProbe(query: ByteArray): Bundle {
            if (query.size !in 12..65_535) {
                return Bundle().apply {
                    putBoolean("approved", false)
                    putString("detail", "La consulta DNS de diagnóstico tiene una longitud inválida.")
                }
            }
            val service = diagnosticInstance
            val snapshot = service?.upstreamSnapshot
            val upstream = snapshot?.client
            if (service == null || !service.isRunning || snapshot == null || upstream == null) {
                return Bundle().apply {
                    putBoolean("approved", false)
                    putString("detail", "El servicio FirewallDNS o sus resolvers protegidos no están activos.")
                }
            }
            val resolverSnapshot = snapshot.resolvers
            val attemptDetails = mutableListOf<String>()
            return when (val result = upstream.exchangeTcp(
                query,
                DnsExchangeCancellation(),
            ) { attempt ->
                // The forced diagnostic path bypasses normal DNS processing, so
                // record the outcome and duration for each physical resolver.
                val resolver = resolverSnapshot.getOrNull(attempt.resolverIndex)
                    ?: "resolver#${attempt.resolverIndex + 1}"
                val elapsedMs = TimeUnit.NANOSECONDS.toMillis(attempt.elapsedNanos)
                val outcome = when (val attemptResult = attempt.result) {
                    is DnsUpstreamResult.Success -> {
                        FirewallDnsTrafficMetrics.upstreamSuccess()
                        "OK ${attemptResult.response.transport}"
                    }
                    is DnsUpstreamResult.Failure -> {
                        FirewallDnsTrafficMetrics.upstreamAttemptFailure(attemptResult.reason)
                        buildString {
                            append(attemptResult.reason)
                            attemptResult.detail?.let { append(" [").append(it).append(']') }
                        }
                    }
                    DnsUpstreamResult.Cancelled -> "cancelada"
                }
                attemptDetails += "$resolver: $outcome (${elapsedMs} ms)"
            }) {
                is DnsUpstreamResult.Success -> Bundle().apply {
                    putBoolean(
                        "approved",
                        result.response.transport == com.firewalldns.engine.dns.DnsUpstreamTransport.TCP,
                    )
                    putString(
                        "detail",
                        "Transporte=${result.response.transport}; respuesta DNS validada. " +
                            "Intentos: ${attemptDetails.joinToString("; ")}",
                    )
                }
                is DnsUpstreamResult.Failure -> {
                    FirewallDnsTrafficMetrics.upstreamFailure()
                    Bundle().apply {
                        putBoolean("approved", false)
                        putString(
                            "detail",
                            "DNS/TCP upstream falló: ${result.reason}. " +
                                "Intentos por resolver: ${attemptDetails.joinToString("; ")}",
                        )
                    }
                }
                DnsUpstreamResult.Cancelled -> {
                    FirewallDnsTrafficMetrics.upstreamCancelled()
                    Bundle().apply {
                        putBoolean("approved", false)
                        putString(
                            "detail",
                            "La prueba DNS/TCP fue cancelada. Intentos: ${attemptDetails.joinToString("; ")}",
                        )
                    }
                }
            }
        }

        const val ACTION_START = "com.firewall.dns.action.START_TUN"
        const val ACTION_STOP = "com.firewall.dns.action.STOP_TUN"

        fun start(context: Context) {
            ContextCompat.startForegroundService(
                context,
                Intent(context, DnsFirewallService::class.java).setAction(ACTION_START)
            )
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, DnsFirewallService::class.java).setAction(ACTION_STOP)
            )
        }
        private const val CHANNEL_ID = "dns_firewall_channel"
        private const val NOTIFICATION_ID = 2001
    }

    override fun onCreate() {
        super.onCreate()
        diagnosticInstance = this
        FirewallRepository.init(applicationContext)
        connectivityManager = getSystemService(ConnectivityManager::class.java)
        registerPhysicalNetworkCallback()

        serviceScope.launch {
            FirewallRepository.cacheInvalidateEvent.collect {
                if (isRunning) installSharedEngine()
                if (isRunning) updateForegroundNotification()
            }
        }
        serviceScope.launch {
            FirewallRepository.rebuildVpnEvent.collect {
                if (isRunning) startVpn()
            }
        }
        serviceScope.launch {
            while (isActive) {
                delay(5_000L)
                val runtime = sharedEngine?.engine ?: continue
                if (!isRunning || activeTunSession?.firestack == null) continue
                runtime.evictIdleFlows()
                FirewallDnsTrafficMetrics.flowSnapshot(runtime.flowMonitor.snapshot(includeFlows = false))
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                FirewallRepository.setShouldRun(false)
                stopVpnAsync()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                FirewallRepository.setShouldRun(true)
                startForegroundNotification()
                Thread { startVpn() }.start()
            }
            null -> {
                stopSelf()
                return START_NOT_STICKY
            }
        }
        return START_NOT_STICKY
    }

    private fun notificationText(): String =
        "FirewallDNS TUN: filtra DNS y controla conexiones TCP/UDP/ICMP por aplicación, IP y puerto; DoH/DoT/DoQ no se descifran"

    private fun buildNotification() = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle("Firewall DNS activo")
        .setContentText(notificationText())
        .setSmallIcon(R.drawable.ic_stat_firewall)
        .setNumber(0)
        .setBadgeIconType(NotificationCompat.BADGE_ICON_NONE)
        .setContentIntent(
            PendingIntent.getActivity(
                this, 0, Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        )
        .addAction(
            android.R.drawable.ic_media_pause,
            "Detener",
            PendingIntent.getService(
                this, 1,
                Intent(this, DnsFirewallService::class.java).apply { action = ACTION_STOP },
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        )
        .setOngoing(true)
        .build()

    private fun startForegroundNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "Firewall DNS", NotificationManager.IMPORTANCE_LOW).apply {
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else 0
        ServiceCompat.startForeground(this, NOTIFICATION_ID, buildNotification(), fgsType)
    }

    private fun updateForegroundNotification() {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification())
    }

    private fun normalizePhysicalLinkMtu(reported: Int): Int =
        reported.takeIf { it in 576..9000 }?.coerceAtLeast(1280) ?: 1500

    private fun currentPhysicalLinkMtu(network: android.net.Network? = selectedPhysicalNetwork): Int {
        val connectivity = getSystemService(android.net.ConnectivityManager::class.java)
        val reported = network?.let { connectivity?.getLinkProperties(it)?.mtu } ?: 0
        return normalizePhysicalLinkMtu(reported)
    }

    private fun buildVpnBuilder(): Builder {
        val builder = Builder()
            .setSession("FirewallDNS")
            .setMtu(1500)
            .addAddress("10.10.10.2", 32)
            .addDnsServer("10.10.10.1")
            .addRoute("10.10.10.1", 32)
            .addAddress("fd00:10:10::2", 128)
            .addDnsServer("fd00:10:10::1")
            .addRoute("fd00:10:10::1", 128)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)

        (FirewallRepository.excludedPackages.value + packageName).forEach { pkg ->
            try {
                builder.addDisallowedApplication(pkg)
            } catch (_: PackageManager.NameNotFoundException) {}
        }
        return builder
    }

    private fun startVpn() = synchronized(vpnLock) {
        closeInterfaceSync()
        val tunDescriptor = buildVpnBuilder().establish()
        if (tunDescriptor == null) {
            FirewallRepository.setRunning(false, "")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        installSharedEngine()
        val engineRuntime = sharedEngine
        val flowAdapter = sharedFlowPolicyAdapter
        if (engineRuntime == null || flowAdapter == null) {
            runCatching { tunDescriptor.close() }
            FirewallRepository.setRunning(false, "")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val (startingSnapshot, startingUpstreamGeneration) = synchronized(upstreamRefreshLock) {
            upstreamSnapshot to upstreamConfigGeneration.get()
        }
        val resolver = startingSnapshot?.resolvers
            ?.takeIf { it.isNotEmpty() }
            ?.joinToString(",") ?: NetworkDns.EMERGENCY_DNS
        val linkMtu = startingSnapshot?.linkMtu ?: currentPhysicalLinkMtu()

        val firestack = runCatching {
            FirestackTunnelAdapter.connect(
                vpnService = this,
                tunDescriptor = tunDescriptor,
                mtu = 1500,
                linkMtu = linkMtu,
                resolver = resolver,
                engine = engineRuntime.engine,
                flowPolicyAdapter = flowAdapter,
                physicalNetworkProvider = { selectedPhysicalNetwork },
                isUidBlocked = AppFirewallManager::isUidBlocked,
                onFlowSnapshot = FirewallDnsTrafficMetrics::flowSnapshot,
                onSocketProtectionResult = FirewallDnsTrafficMetrics::firestackSocketProtectionResult,
                onSocketBindingResult = FirewallDnsTrafficMetrics::firestackSocketBindingResult,
                onDnsDecision = { domain, qType, uid, reason, action ->
                    when (action) {
                        PolicyAction.BLOCK -> FirewallDnsTrafficMetrics.dnsBlocked()
                        PolicyAction.OBSERVE -> FirewallDnsTrafficMetrics.dnsObserved()
                        PolicyAction.ALLOW -> FirewallDnsTrafficMetrics.dnsAllowed()
                    }
                    FirewallRepository.addLog(
                        domain = domain,
                        qType = DnsPacketEngine.queryTypeToString(qType),
                        isBlocked = action == PolicyAction.BLOCK,
                        reason = reason,
                        appName = resolveAppName(uid ?: Process.INVALID_UID),
                    )
                },
            )
        }.getOrNull()

        // Fail closed: never report an active firewall or start a second packet
        // engine if the one production FirewallDNS/Firestack stack cannot attach.
        if (firestack == null) {
            runCatching { tunDescriptor.close() }
            isRunning = false
            sharedEngine = null
            sharedFlowPolicyAdapter = null
            upstreamSnapshot = null
            FirewallRepository.setRunning(false, "")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        firestackResolverGeneration.set(startingUpstreamGeneration)
        activeTunSession = TunSession(tunDescriptor, firestack)
        isRunning = true
        FirewallRepository.setRunning(true, "FirewallDNS Engine (Firestack/gVisor)")
        FirewallDnsTrafficMetrics.firestackStarted()

        // Reconcile any physical-network change that happened during startup.
        refreshSharedUpstream()
        updateForegroundNotification()
    }

    private fun installSharedEngine() {
        // FirewallDNS always uses its own unified policy runtime.
        val existing = sharedEngine
        if (existing != null) {
            existing.engine.replaceRules(FirewallRepository.enginePolicyRules())
            existing.engine.replaceThreatAnalyzer(
                if (FirewallRepository.isSmartModeEnabled()) {
                    com.firewalldns.engine.threat.ThreatAnalyzer()
                } else {
                    com.firewalldns.engine.threat.ThreatAnalyzer(emptyList(), emptyList())
                },
            )
            return
        }

        val runtime = runCatching {
            AndroidEngineRuntime(
                this,
                FirewallRepository.isSmartModeEnabled(),
                onSocketProtectionResult = { protocol, wasProtected ->
                    FirewallDnsTrafficMetrics.socketProtectionResult(protocol, wasProtected)
                },
                physicalNetworkProvider = { selectedPhysicalNetwork },
            ).also {
                it.engine.replaceRules(FirewallRepository.enginePolicyRules())
            }
        }.getOrNull()
        sharedEngine = runtime
        sharedFlowPolicyAdapter = runtime?.createFlowPolicyAdapter(
            resolvePackage = ::resolvePackageName,
            isUidBlocked = AppFirewallManager::isUidBlocked,
            networkGeneration = { physicalNetworkGeneration.get() },
        )
        synchronized(upstreamRefreshLock) {
            upstreamSnapshot = null
            refreshSharedUpstreamLocked()
        }
    }

    /**
     * Android may replace the physical network while this VPN remains the default.
     * Rebuild only the protected DNS clients; never tear down or re-establish TUN.
     */
    private fun registerPhysicalNetworkCallback() {
        if (physicalNetworkCallback != null) return
        val request = android.net.NetworkRequest.Builder()
            .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            private fun refresh() {
                serviceScope.launch(Dispatchers.IO) {
                    if (sharedEngine != null) refreshSharedUpstream()
                }
            }

            override fun onAvailable(network: android.net.Network) = refresh()
            override fun onLinkPropertiesChanged(
                network: android.net.Network,
                linkProperties: android.net.LinkProperties
            ) = refresh()
            override fun onCapabilitiesChanged(
                network: android.net.Network,
                networkCapabilities: android.net.NetworkCapabilities
            ) = refresh()
            override fun onLost(network: android.net.Network) = refresh()
        }
        try {
            connectivityManager.registerNetworkCallback(request, callback)
            physicalNetworkCallback = callback
        } catch (_: Throwable) {
            // Keep the startup resolver selection if the platform rejects callback registration.
        }
    }

    private fun refreshSharedUpstream() {
        synchronized(upstreamRefreshLock) {
            refreshSharedUpstreamLocked()
        }
    }

    private fun refreshSharedUpstreamLocked() {
        val runtime = sharedEngine ?: return
        // Read resolver addresses and their Android Network from one snapshot:
        // a network handover must never pair DNS from Wi-Fi with sockets on cellular.
        val networkSnapshot = NetworkDns.activeSnapshot(this)
        val physicalNetwork = networkSnapshot.network
        val linkMtu = normalizePhysicalLinkMtu(networkSnapshot.linkMtu)
        if (selectedPhysicalNetwork != physicalNetwork) physicalNetworkGeneration.incrementAndGet()
        selectedPhysicalNetwork = physicalNetwork
        // Android asks VpnService to publish explicitly bound underlying networks.
        runCatching {
            setUnderlyingNetworks(physicalNetwork?.let { arrayOf(it) })
        }

        val discovered = networkSnapshot.resolvers.ifEmpty {
            listOf(NetworkDns.EMERGENCY_DNS)
        }
        val current = upstreamSnapshot
        // A resolver list can be identical on two different networks. Network
        // identity is part of the generation because sockets must bind to the
        // same physical network that supplied those resolver addresses.
        if (current != null &&
            discovered == current.resolvers &&
            physicalNetwork == current.physicalNetwork
        ) {
            val stack = activeTunSession?.firestack
            val generation = upstreamConfigGeneration.get()
            val needsResolverRebind = stack != null && firestackResolverGeneration.get() != generation
            val updateSucceeded = when {
                stack == null -> true
                needsResolverRebind -> stack.updatePhysicalNetworkResolver(discovered.joinToString(","), linkMtu)
                linkMtu != current.linkMtu -> stack.updateLinkMtu(linkMtu)
                else -> true
            }
            if (updateSucceeded) {
                if (needsResolverRebind) firestackResolverGeneration.set(generation)
                upstreamSnapshot = current.copy(linkMtu = linkMtu)
            } else {
                FirewallDnsTrafficMetrics.upstreamFailure()
            }
            return
        }
        val replacement = runCatching {
            runtime.createDnsFailover(
                upstreams = discovered.map { address ->
                    DnsUpstreamConfig(address, timeoutMillis = 2_000)
                },
                physicalNetwork = physicalNetwork,
            )
        }.getOrNull() ?: return

        // Publish client, resolver labels, physical Network and MTU as one generation.
        // In-flight exchanges keep the old client pinned to its original Network.
        upstreamConfigGeneration.incrementAndGet()
        upstreamSnapshot = UpstreamSnapshot(replacement, discovered.toList(), physicalNetwork, linkMtu)
        FirewallDnsTrafficMetrics.upstreamResolversChanged(discovered)
        // Rebind DNS to the resolver from this exact physical-network generation.
        // Sockets created on the previous Android Network cannot be rebound in place:
        // restart Firestack's netstack on the same TUN to retire stale TCP/UDP flows.
        val physicalNetworkChanged = current != null && physicalNetwork != current.physicalNetwork
        activeTunSession?.firestack?.let { stack ->
            val stackReady = stack.reconfigurePhysicalNetwork(
                resolver = discovered.joinToString(","),
                linkMtu = linkMtu,
                networkChanged = physicalNetworkChanged,
            )
            if (stackReady) {
                firestackResolverGeneration.set(upstreamConfigGeneration.get())
            } else {
                FirewallDnsTrafficMetrics.upstreamFailure()
                if (physicalNetworkChanged) scheduleFirestackNetworkRecovery()
            }
        }
    }

    /** Rebuild the active TUN session if Firestack cannot restart after a network handover. */
    private fun scheduleFirestackNetworkRecovery() {
        if (!networkHandoverRecoveryScheduled.compareAndSet(false, true)) return
        serviceScope.launch(Dispatchers.IO) {
            try {
                if (isRunning) startVpn()
            } finally {
                networkHandoverRecoveryScheduled.set(false)
            }
        }
    }

    private fun resolvePackageName(uid: Int): String? =
        if (uid < 0) null else runCatching { packageManager.getPackagesForUid(uid)?.singleOrNull() }.getOrNull()

    private fun resolveAppName(uid: Int): String {
        if (uid == Process.INVALID_UID || uid < 0) return "Sistema / DNS"
        if (uid == 0) return "Sistema (root)"
        if (uid == Process.SYSTEM_UID) return "Sistema Android"
        return uidAppCache.getOrPut(uid) {
            try {
                val pkgs = packageManager.getPackagesForUid(uid)
                if (!pkgs.isNullOrEmpty()) {
                    val info = packageManager.getApplicationInfo(pkgs[0], 0)
                    packageManager.getApplicationLabel(info).toString()
                } else "UID $uid"
            } catch (_: Exception) { "UID $uid" }
        }
    }

    private fun closeInterfaceSync() {
        isRunning = false
        FirewallRepository.setRunning(false)
        sharedEngine = null
        upstreamSnapshot = null
        selectedPhysicalNetwork = null
        physicalNetworkGeneration.incrementAndGet()
        upstreamConfigGeneration.incrementAndGet()
        firestackResolverGeneration.set(-1L)
        sharedFlowPolicyAdapter = null
        FirewallDnsTrafficMetrics.upstreamResolversChanged(emptyList())

        val session = activeTunSession
        activeTunSession = null
        if (session != null) {
            session.active.set(false)
            // Stop the one production stack before closing its TUN descriptor.
            session.firestack.close()
            FirewallDnsTrafficMetrics.firestackStopped()
            runCatching { session.descriptor.close() }
        }
    }

    private fun stopVpnAsync() {
        isRunning = false
        Thread {
            synchronized(vpnLock) {
                closeInterfaceSync()
            }
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
            stopSelf()
        }.start()
    }

    override fun onRevoke() {
        FirewallRepository.setShouldRun(false)
        stopVpnAsync()
        super.onRevoke()
    }

    override fun onDestroy() {
        if (diagnosticInstance === this) diagnosticInstance = null
        physicalNetworkCallback?.let { callback ->
            runCatching { connectivityManager.unregisterNetworkCallback(callback) }
        }
        physicalNetworkCallback = null
        serviceScope.cancel()
        isRunning = false
        Thread {
            synchronized(vpnLock) { closeInterfaceSync() }
        }.start()
        super.onDestroy()
    }
}
