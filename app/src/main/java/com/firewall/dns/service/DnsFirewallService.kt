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
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.firewall.dns.MainActivity
import com.firewall.dns.BuildConfig
import com.firewall.dns.R
import com.firewall.dns.data.repository.FirewallRepository
import com.firewall.dns.domain.engine.AppFirewallManager
import com.firewall.dns.domain.engine.DnsPacketEngine
import com.firewall.dns.domain.engine.TunTransportPacketParser
import com.firewalldns.engine.android.AndroidEngineRuntime
import com.firewalldns.engine.android.AndroidFlowPolicyAdapter
import com.firewalldns.engine.android.FirestackTunnelAdapter
import com.firewalldns.engine.android.FragmentReassemblerConfig
import com.firewalldns.engine.android.IpFragmentReassembler
import com.firewalldns.engine.android.NativeTcpDnsTransport
import com.firewalldns.engine.android.DnsSocketProtectionProtocol
import com.firewalldns.engine.android.SmoltcpDnsTcpCoordinator
import com.firewalldns.engine.android.DnsTcpPacketClassifier
import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.dns.DnsEvaluation
import com.firewalldns.engine.dns.DnsExchangeCancellation
import com.firewalldns.engine.dns.DnsUpstreamConfig
import com.firewalldns.engine.dns.DnsUpstreamFailoverClient
import com.firewalldns.engine.dns.DnsUpstreamResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class DnsFirewallService : VpnService() {

    private class TunSession(
        val descriptor: ParcelFileDescriptor,
        val input: FileInputStream?,
        val output: FileOutputStream?,
        val firestack: FirestackTunnelAdapter? = null,
    ) {
        val active = AtomicBoolean(true)
        val inFlightWorkers = AtomicInteger(0)
        val tcpOwnerWake = ArrayBlockingQueue<Unit>(1)
        val fragmentReassembler = IpFragmentReassembler(
            config = FragmentReassemblerConfig(maxReassembledPacketBytes = 1500),
        )
        @Volatile var tcpCoordinator: SmoltcpDnsTcpCoordinator? = null
        @Volatile var tcpOwner: Thread? = null
        @Volatile var reader: Thread? = null
    }

    @Volatile
    private var activeTunSession: TunSession? = null
    // El lector TUN nunca ejecuta trabajo DNS: si la cola se llena, el paquete
    // se contabiliza como rechazado en lugar de bloquear la lectura del túnel.
    private val executor = ThreadPoolExecutor(
        4, 8, 15L, TimeUnit.SECONDS,
        ArrayBlockingQueue(256),
        ThreadPoolExecutor.AbortPolicy()
    ).apply {
        allowCoreThreadTimeOut(true)
    }
    private val writeLock = Any()
    private val vpnLock = Any()
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Volatile
    private var isRunning = false

    private data class CachedDns(val response: ByteArray, val expiresAt: Long)
    private val dnsCache = ConcurrentHashMap<String, CachedDns>()
    private val uidAppCache = ConcurrentHashMap<Int, String>()

    private lateinit var connectivityManager: ConnectivityManager
    @Volatile private var sharedEngine: AndroidEngineRuntime? = null
    @Volatile private var sharedFlowPolicyAdapter: AndroidFlowPolicyAdapter? = null
    private val physicalNetworkGeneration = AtomicLong(0L)
    private data class UpstreamSnapshot(
        val client: DnsUpstreamFailoverClient,
        val resolvers: List<String>,
        val physicalNetwork: android.net.Network?,
    )
    /**
     * Client and resolver labels are one immutable publication. Keeping them
     * together prevents diagnostics from labelling attempts with a newer network.
     */
    @Volatile private var upstreamSnapshot: UpstreamSnapshot? = null
    @Volatile private var selectedPhysicalNetwork: android.net.Network? = null
    @Volatile private var physicalNetworkCallback: ConnectivityManager.NetworkCallback? = null
    private val upstreamRefreshLock = Any()

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
        private const val CACHE_TTL_MS = 60_000L

        /** Paquetes descartados explícitamente por saturación de la cola TUN. */
        val queueRejectedPackets = AtomicLong(0L)

        /** Fallos inesperados al procesar un paquete en un worker. */
        val packetProcessingErrors = AtomicLong(0L)

        /** Fallos al escribir respuestas en el descriptor TUN. */
        val packetWriteErrors = AtomicLong(0L)

        private val TRAPPED_IPV4_DNS = listOf("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1")
        private val TRAPPED_IPV6_DNS = listOf(
            "2001:4860:4860::8888", "2001:4860:4860::8844",
            "2606:4700:4700::1111", "2606:4700:4700::1001"
        )
    }

    override fun onCreate() {
        super.onCreate()
        diagnosticInstance = this
        FirewallRepository.init(applicationContext)
        connectivityManager = getSystemService(ConnectivityManager::class.java)
        registerPhysicalNetworkCallback()

        serviceScope.launch {
            FirewallRepository.cacheInvalidateEvent.collect {
                dnsCache.clear()
                if (isRunning) installSharedEngine()
                if (isRunning) updateForegroundNotification()
            }
        }
        serviceScope.launch {
            FirewallRepository.rebuildVpnEvent.collect {
                if (isRunning) startVpn()
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
        "FirewallDNS TUN: filtra consultas DNS; el tráfico TCP/UDP general y DoH/DoT no se inspeccionan en esta etapa"

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

    private fun buildVpnBuilder(fullTunnel: Boolean): Builder {
        val upstream = FirewallRepository.getUpstreamDns()
        val builder = Builder()
            .setSession("FirewallDNS")
            .setMtu(1500)
            .addAddress("10.10.10.2", 32)
            .addDnsServer("10.10.10.1")
            .addRoute("10.10.10.1", 32)
            .addAddress("fd00:10:10::2", 128)
            .addDnsServer("fd00:10:10::1")
            .addRoute("fd00:10:10::1", 128)

        if (fullTunnel) {
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        } else {
            TRAPPED_IPV4_DNS.filter { it != upstream }.forEach { builder.addRoute(it, 32) }
            TRAPPED_IPV6_DNS.forEach { builder.addRoute(it, 128) }
        }

        (FirewallRepository.excludedPackages.value + packageName).forEach { pkg ->
            try {
                builder.addDisallowedApplication(pkg)
            } catch (_: PackageManager.NameNotFoundException) {}
        }
        return builder
    }

    private fun startVpn() = synchronized(vpnLock) {
        closeInterfaceSync()
        val fullTunnelDescriptor = buildVpnBuilder(fullTunnel = true).establish()
        if (fullTunnelDescriptor == null) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        installSharedEngine()
        val engineRuntime = sharedEngine
        val flowAdapter = sharedFlowPolicyAdapter
        val resolver = upstreamSnapshot?.resolvers?.takeIf { it.isNotEmpty() }?.joinToString(",") ?: NetworkDns.EMERGENCY_DNS
        val firestack = if (engineRuntime != null && flowAdapter != null) {
            runCatching {
                FirestackTunnelAdapter.connect(
                    vpnService = this,
                    tunDescriptor = fullTunnelDescriptor,
                    mtu = 1500,
                    resolver = resolver,
                    engine = engineRuntime.engine,
                    flowPolicyAdapter = flowAdapter,
                    physicalNetworkProvider = { selectedPhysicalNetwork },
                    resolvePackage = ::resolvePackageName,
                    isUidBlocked = AppFirewallManager::isUidBlocked,
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
        } else null

        val established = if (firestack != null) {
            fullTunnelDescriptor
        } else {
            // Never leave a full-device route without a functioning packet stack.
            runCatching { fullTunnelDescriptor.close() }
            buildVpnBuilder(fullTunnel = false).establish()
        }
        if (established == null) {
            firestack?.close()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        isRunning = true
        FirewallRepository.setRunning(
            true,
            if (firestack != null) "FirewallDNS TUN (Firestack/gVisor)" else "FirewallDNS TUN (DNS fallback)",
        )
        val session = TunSession(
            descriptor = established,
            input = if (firestack == null) FileInputStream(established.fileDescriptor) else null,
            output = if (firestack == null) FileOutputStream(established.fileDescriptor) else null,
            firestack = firestack,
        )
        activeTunSession = session

        if (firestack != null) {
            // Firestack owns packet ingress/egress on the duplicated TUN descriptor.
            // The legacy reader and smoltcp DNS/TCP laboratory must not compete for packets.
            updateForegroundNotification()
            return
        }

        val upstreamClient = upstreamSnapshot?.client
        if (engineRuntime != null && upstreamClient != null) {
            val nativeTransport = runCatching {
                NativeTcpDnsTransport.create(
                    mtu = 1500,
                    tunDnsIpv4 = byteArrayOf(10, 10, 10, 1),
                    tunClientIpv4 = byteArrayOf(10, 10, 10, 2),
                    tunDnsIpv6 = byteArrayOf(
                        0xfd.toByte(), 0, 0, 0x10, 0, 0x10, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 1,
                    ),
                    tunClientIpv6 = byteArrayOf(
                        0xfd.toByte(), 0, 0, 0x10, 0, 0x10, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 2,
                    ),
                    maxSessions = 64,
                )
            }.getOrNull()
            if (nativeTransport != null) {
                val appUidByPackage = ConcurrentHashMap<String, Int>()
                val tcpCoordinator = runCatching {
                    SmoltcpDnsTcpCoordinator(
                        transport = nativeTransport,
                        evaluateDns = { query, appPackage ->
                            val base = (sharedEngine ?: engineRuntime).engine.evaluateDns(query, appPackage)
                            val uid = appPackage?.let(appUidByPackage::get) ?: Process.INVALID_UID
                            val appBlocked = uid >= 0 && AppFirewallManager.isUidBlocked(uid)
                            val effective = when {
                                base is DnsEvaluation.Rejected -> base
                                appBlocked && base is DnsEvaluation.Forward -> {
                                    val parsed = DnsPacketEngine.parseDnsQuery(query)
                                    if (parsed == null) base else DnsEvaluation.Blocked(
                                        base.question,
                                        base.decision.copy(action = PolicyAction.BLOCK, reason = "app_uid_blocked"),
                                        DnsPacketEngine.buildNxDomainResponse(query, parsed.questionEndOffset),
                                    )
                                }
                                else -> base
                            }
                            val parsedForLog = DnsPacketEngine.parseDnsQuery(query)
                            when (effective) {
                                is DnsEvaluation.Blocked -> FirewallDnsTrafficMetrics.dnsBlocked()
                                is DnsEvaluation.Forward -> {
                                    if (effective.decision.action == PolicyAction.OBSERVE) {
                                        FirewallDnsTrafficMetrics.dnsObserved()
                                    } else {
                                        FirewallDnsTrafficMetrics.dnsAllowed()
                                    }
                                }
                                is DnsEvaluation.Rejected -> FirewallDnsTrafficMetrics.dnsRejected()
                            }
                            if (parsedForLog != null) {
                                val reason = when (effective) {
                                    is DnsEvaluation.Blocked -> effective.decision.reason
                                    is DnsEvaluation.Forward -> effective.decision.reason
                                    is DnsEvaluation.Rejected -> effective.reason
                                }
                                FirewallRepository.addLog(
                                    domain = parsedForLog.domain,
                                    qType = DnsPacketEngine.queryTypeToString(parsedForLog.qType),
                                    isBlocked = effective is DnsEvaluation.Blocked,
                                    reason = reason,
                                    appName = resolveAppName(uid),
                                )
                            }
                            effective
                        },
                        resolveAppPackage = { sourceAddress, sourcePort, destinationAddress, destinationPort ->
                            val uid = resolveAppUid(
                                OsConstants.IPPROTO_TCP,
                                sourceAddress,
                                sourcePort,
                                destinationAddress,
                                destinationPort,
                            )
                            resolvePackageName(uid)?.also { appUidByPackage[it] = uid }
                        },
                        exchangeUpstream = { query, cancellation ->
                            val result = (upstreamSnapshot?.client ?: upstreamClient).exchange(query, cancellation) { attempt ->
                                (attempt.result as? DnsUpstreamResult.Failure)?.let {
                                    FirewallDnsTrafficMetrics.upstreamAttemptFailure(it.reason)
                                }
                            }
                            when (result) {
                                is DnsUpstreamResult.Success -> FirewallDnsTrafficMetrics.upstreamSuccess()
                                is DnsUpstreamResult.Failure -> FirewallDnsTrafficMetrics.upstreamFailure()
                                DnsUpstreamResult.Cancelled -> FirewallDnsTrafficMetrics.upstreamCancelled()
                            }
                            result
                        },
                        onTunPacket = { packet -> writePacket(session, packet) },
                        wakeOwner = { session.tcpOwnerWake.offer(Unit) },
                        maxSessions = 64,
                    )
                }.getOrNull()
                if (tcpCoordinator != null) {
                    session.tcpCoordinator = tcpCoordinator
                    session.tcpOwner = Thread({
                        while (session.active.get() && isRunning && !Thread.currentThread().isInterrupted) {
                            try {
                                session.tcpOwnerWake.poll(10, TimeUnit.MILLISECONDS)
                            } catch (_: InterruptedException) {
                                break
                            }
                            if (!session.active.get() || !isRunning) break
                            runCatching { tcpCoordinator.pollOwner() }
                                .onSuccess(FirewallDnsTrafficMetrics::smoltcpSnapshot)
                                .onFailure {
                                    packetProcessingErrors.incrementAndGet()
                                    FirewallDnsTrafficMetrics.workerError()
                                }
                        }
                    }, "FirewallDNS-smoltcp-owner").apply { start() }
                    FirewallDnsTrafficMetrics.smoltcpStarted()
                } else {
                    nativeTransport.close()
                }
            }
        }

        session.reader = Thread({
            val buffer = ByteArray(4096)
            try {
                while (session.active.get() && isRunning && !Thread.currentThread().isInterrupted) {
                    val length = session.input?.read(buffer) ?: break
                    if (length < 0) break
                    if (length > 0 && session.active.get()) {
                        FirewallDnsTrafficMetrics.packetRead()
                        val copy = buffer.copyOf(length)
                        val fragmentResult = session.fragmentReassembler.process(copy)
                        session.fragmentReassembler.evictExpired()
                        FirewallDnsTrafficMetrics.fragmentSnapshot(session.fragmentReassembler.metrics())
                        val normalized = when (val result = fragmentResult) {
                            IpFragmentReassembler.Result.Pending -> continue
                            is IpFragmentReassembler.Result.Dropped -> {
                                FirewallDnsTrafficMetrics.parserRejected()
                                continue
                            }
                            is IpFragmentReassembler.Result.Ready -> result.packet.copyOf(result.length)
                        }

                        // Keep TCP SYN/ACK/data order: the one TUN reader feeds smoltcp
                        // directly. DNS policy and upstream work run on per-session workers.
                        val tcpCoordinator = session.tcpCoordinator
                        if (tcpCoordinator != null && DnsTcpPacketClassifier.isClientDnsTcpPacket(normalized)) {
                            if (((normalized[0].toInt() ushr 4) and 0x0f) == 6) {
                                FirewallDnsTrafficMetrics.ipv6Packet()
                            } else {
                                FirewallDnsTrafficMetrics.ipv4Packet()
                            }
                            FirewallDnsTrafficMetrics.tcpDns()
                            if (tcpCoordinator.offerPacket(normalized) != NativeTcpDnsTransport.RESULT_OK) {
                                queueRejectedPackets.incrementAndGet()
                                FirewallDnsTrafficMetrics.queueRejected()
                            }
                        } else {
                            try {
                                executor.execute {
                                    session.inFlightWorkers.incrementAndGet()
                                    try {
                                        // Segunda comprobación: el cierre puede ocurrir tras encolar.
                                        if (session.active.get()) handlePacket(normalized, session)
                                    } catch (_: Exception) {
                                        packetProcessingErrors.incrementAndGet()
                                        FirewallDnsTrafficMetrics.workerError()
                                    } finally {
                                        session.inFlightWorkers.decrementAndGet()
                                    }
                                }
                            } catch (_: RejectedExecutionException) {
                                queueRejectedPackets.incrementAndGet()
                                FirewallDnsTrafficMetrics.queueRejected()
                            }
                        }
                    }
                }
            } catch (_: IOException) {
                // Cerrar el descriptor desbloquea read() durante el apagado normal.
            }
        }, "FirewallDNS-TUN-reader").apply { start() }
    }

    private fun handlePacket(req: ByteArray, session: TunSession) {
        val packet = TunTransportPacketParser.parse(req) ?: run {
            FirewallDnsTrafficMetrics.parserRejected()
            return
        }
        if (packet.isIpv6) FirewallDnsTrafficMetrics.ipv6Packet() else FirewallDnsTrafficMetrics.ipv4Packet()
        if (packet.destinationPort != 53) {
            if (packet.protocol == 6) FirewallDnsTrafficMetrics.nonDnsTcp() else FirewallDnsTrafficMetrics.nonDnsUdp()
            return
        }

        val srcIp = packet.sourceAddress
        val dstIp = packet.destinationAddress
        val srcPort = packet.sourcePort
        val dstPort = packet.destinationPort

        if (packet.protocol == 6) {
            FirewallDnsTrafficMetrics.tcpDns()
            // Fallback seguro cuando el paquete no pudo entrar en la ruta smoltcp
            // (transporte nativo no disponible o formato no soportado): responder RST
            // solo a segmentos TCP/53 estructuralmente válidos.
            val rst = DnsPacketEngine.buildTcpRstResponse(req, packet)
            if (rst != null) {
                FirewallDnsTrafficMetrics.tcpRstSent()
                writePacket(session, rst)
            } else {
                FirewallDnsTrafficMetrics.tcpRstSuppressed()
            }
            return
        }
        if (packet.protocol != 17) {
            FirewallDnsTrafficMetrics.unsupportedTransport()
            return
        }
        FirewallDnsTrafficMetrics.dnsUdpPacket()

        val dnsPayload = req.copyOfRange(packet.payloadOffset, packet.ipTotalLength)
        val query = DnsPacketEngine.parseDnsQuery(dnsPayload) ?: run {
            FirewallDnsTrafficMetrics.malformedDns()
            return
        }
        val appUid = resolveAppUid(OsConstants.IPPROTO_UDP, srcIp, srcPort, dstIp, dstPort)
        val appName = resolveAppName(appUid)
        val appPackage = resolvePackageName(appUid)
        val evaluation = sharedEngine?.engine?.evaluateDns(dnsPayload, appPackage)
        val engineDecision = when (evaluation) {
            is DnsEvaluation.Blocked -> true to evaluation.decision.reason
            is DnsEvaluation.Forward -> false to evaluation.decision.reason
            is DnsEvaluation.Rejected -> {
                FirewallDnsTrafficMetrics.dnsRejected()
                return
            }
            null -> FirewallRepository.evaluateDomain(query.domain)
        }
        val appBlocked = appUid >= 0 && AppFirewallManager.isUidBlocked(appUid)
        val policyWouldBlock = appBlocked || engineDecision.first
        val shouldBlock = policyWouldBlock
        val policyIsObserve = (evaluation as? DnsEvaluation.Forward)?.decision?.action == PolicyAction.OBSERVE
        when {
            shouldBlock -> FirewallDnsTrafficMetrics.dnsBlocked()
            policyIsObserve -> FirewallDnsTrafficMetrics.dnsObserved()
            else -> FirewallDnsTrafficMetrics.dnsAllowed()
        }
        val finalReason = if (appBlocked) "DNS bloqueado para la aplicación" else engineDecision.second

        var upstreamWasCancelled = false
        val dnsResponse: ByteArray?
        if (shouldBlock) {
            dnsResponse = DnsPacketEngine.buildNxDomainResponse(dnsPayload, query.questionEndOffset)
        } else {
            // Use one network generation for both the cache identity and the exchange.
            val queryUpstream = upstreamSnapshot
            val cacheKey = "${query.domain.lowercase()}:${query.qType}:${queryUpstream?.resolvers.orEmpty().joinToString(",")}"
            val now = System.currentTimeMillis()
            val cached = dnsCache[cacheKey]?.takeIf { it.expiresAt > now }
            val cachedResponse = cached?.response?.copyOf()?.apply {
                this[0] = dnsPayload[0]
                this[1] = dnsPayload[1]
            }?.takeIf { DnsPacketEngine.matchesDnsResponse(dnsPayload, it) }
            if (cachedResponse != null) {
                FirewallDnsTrafficMetrics.cacheHit()
                dnsResponse = cachedResponse
            } else {
                FirewallDnsTrafficMetrics.cacheMiss()
                val upstreamResult = queryUpstream?.client?.exchange(
                    dnsPayload,
                    DnsExchangeCancellation(),
                ) { attempt ->
                    (attempt.result as? DnsUpstreamResult.Failure)?.let {
                        FirewallDnsTrafficMetrics.upstreamAttemptFailure(it.reason)
                    }
                }
                dnsResponse = when (upstreamResult) {
                    is DnsUpstreamResult.Success -> upstreamResult.response.message
                    is DnsUpstreamResult.Failure -> forwardDnsQuery(dnsPayload, queryUpstream)
                    DnsUpstreamResult.Cancelled -> {
                        upstreamWasCancelled = true
                        null
                    }
                    null -> forwardDnsQuery(dnsPayload, queryUpstream)
                }
                if (dnsResponse != null) {
                    FirewallDnsTrafficMetrics.upstreamSuccess()
                    if (dnsCache.size > 600) dnsCache.clear()
                    dnsCache[cacheKey] = CachedDns(dnsResponse, now + CACHE_TTL_MS)
                } else {
                    if (upstreamWasCancelled) {
                        FirewallDnsTrafficMetrics.upstreamCancelled()
                    } else {
                        FirewallDnsTrafficMetrics.upstreamFailure()
                    }
                }
            }
        }

        FirewallRepository.addLog(
            domain = query.domain,
            qType = DnsPacketEngine.queryTypeToString(query.qType),
            isBlocked = shouldBlock,
            reason = finalReason,
            appName = appName
        )

        if (dnsResponse != null) {
            val responsePacket = if (packet.isIpv6) {
                DnsPacketEngine.buildIpv6UdpResponse(srcIp, dstIp, srcPort, dstPort, dnsResponse)
            } else {
                DnsPacketEngine.buildIpv4UdpResponse(req, srcIp, dstIp, srcPort, dstPort, dnsResponse)
            }
            FirewallDnsTrafficMetrics.responseBuilt()
            writePacket(session, responsePacket)
        } else {
            FirewallDnsTrafficMetrics.noDnsResponse()
        }
    }

    private fun writePacket(session: TunSession, data: ByteArray) {
        synchronized(writeLock) {
            // Una respuesta de una sesión anterior nunca debe entrar en el TUN nuevo.
            if (!session.active.get()) return
            try {
                val output = session.output ?: return
                output.write(data)
                FirewallDnsTrafficMetrics.responseWritten()
            } catch (_: IOException) {
                packetWriteErrors.incrementAndGet()
                FirewallDnsTrafficMetrics.writeError()
            }
        }
    }

    private fun resolveAppUid(protocol: Int, srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return Process.INVALID_UID
        return try {
            connectivityManager.getConnectionOwnerUid(
                protocol,
                InetSocketAddress(InetAddress.getByAddress(srcIp), srcPort),
                InetSocketAddress(InetAddress.getByAddress(dstIp), dstPort)
            )
        } catch (_: Exception) {
            Process.INVALID_UID
        }
    }


    private fun installSharedEngine() {
        if (!BuildConfig.USE_SHARED_ENGINE) {
            sharedEngine = null
            sharedFlowPolicyAdapter = null
            upstreamSnapshot = null
            FirewallDnsTrafficMetrics.upstreamResolversChanged(emptyList())
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
                    if (isRunning) refreshSharedUpstream()
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
        ) return
        val replacement = runCatching {
            runtime.createDnsFailover(
                upstreams = discovered.map { address ->
                    DnsUpstreamConfig(address, timeoutMillis = 2_000)
                },
                physicalNetwork = physicalNetwork,
            )
        }.getOrNull() ?: return

        // Publish client, resolver labels and physical Network as one generation.
        // In-flight exchanges keep the old client pinned to its original Network.
        upstreamSnapshot = UpstreamSnapshot(replacement, discovered.toList(), physicalNetwork)
        FirewallDnsTrafficMetrics.upstreamResolversChanged(discovered)
        // Rebind Firestack's default DNS transport to the resolver from this exact
        // physical-network generation without restarting the TUN/netstack.
        activeTunSession?.firestack?.let { stack ->
            if (!stack.updatePhysicalNetworkResolver(discovered.joinToString(","))) {
                FirewallDnsTrafficMetrics.upstreamFailure()
            }
        }
        dnsCache.clear()
    }

    private fun resolvePackageName(uid: Int): String? =
        if (uid < 0) null else runCatching { packageManager.getPackagesForUid(uid)?.firstOrNull() }.getOrNull()

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

    private fun forwardDnsQuery(
        dnsPayload: ByteArray,
        networkGeneration: UpstreamSnapshot?,
    ): ByteArray? {
        var socket: DatagramSocket? = null
        return try {
            socket = DatagramSocket()
            socket.soTimeout = 3500
            // Keep the legacy UDP fallback on the same physical Network and
            // resolver generation as the primary exchange.
            networkGeneration?.physicalNetwork?.bindSocket(socket)
            val wasProtected = try {
                protect(socket)
            } catch (error: Throwable) {
                FirewallDnsTrafficMetrics.socketProtectionResult(DnsSocketProtectionProtocol.UDP, false)
                throw error
            }
            FirewallDnsTrafficMetrics.socketProtectionResult(DnsSocketProtectionProtocol.UDP, wasProtected)
            if (!wasProtected) return null
            val resolver = networkGeneration?.resolvers?.firstOrNull() ?: NetworkDns.EMERGENCY_DNS
            val addr = InetAddress.getByName(resolver)
            // A connected UDP socket accepts datagrams only from this upstream endpoint.
            socket.connect(addr, 53)
            socket.send(DatagramPacket(dnsPayload, dnsPayload.size))
            val buf = ByteArray(4096)
            val response = DatagramPacket(buf, buf.size)
            socket.receive(response)
            if (response.length < 12) return null
            val answer = buf.copyOf(response.length)
            answer.takeIf { DnsPacketEngine.matchesDnsResponse(dnsPayload, it) }
        } catch (_: Exception) {
            null
        } finally {
            socket?.close()
        }
    }

    private fun closeInterfaceSync() {
        FirewallDnsTrafficMetrics.smoltcpStopped()
        isRunning = false
        FirewallRepository.setRunning(false)
        sharedEngine = null
        upstreamSnapshot = null
        selectedPhysicalNetwork = null
        physicalNetworkGeneration.incrementAndGet()
        sharedFlowPolicyAdapter = null
        FirewallDnsTrafficMetrics.upstreamResolversChanged(emptyList())

        val session = activeTunSession
        activeTunSession = null
        if (session != null) {
            // Invalidar primero: workers antiguos ya no pueden escribir respuestas.
            session.active.set(false)

            // Stop the user-space stack before closing either reference to the TUN fd.
            session.firestack?.close()
            synchronized(writeLock) {
                try { session.input?.close() } catch (_: IOException) {}
                try { session.output?.close() } catch (_: IOException) {}
                try { session.descriptor.close() } catch (_: IOException) {}
            }

            session.reader?.interrupt()
            if (session.reader !== Thread.currentThread()) {
                try {
                    session.reader?.join(1_000L)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }

            // Espera acotada: el cierre no queda a merced de una consulta upstream lenta.
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500)
            while (session.inFlightWorkers.get() > 0 && System.nanoTime() < deadline) {
                try {
                    Thread.sleep(10L)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                }
            }
            session.tcpOwner?.interrupt()
            if (session.tcpOwner !== Thread.currentThread()) {
                try { session.tcpOwner?.join(1_000L) } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
            session.tcpCoordinator?.close()
            session.fragmentReassembler.clear()
            session.tcpCoordinator?.metrics()?.let(FirewallDnsTrafficMetrics::smoltcpSnapshot)
            FirewallDnsTrafficMetrics.smoltcpStopped()
            session.tcpCoordinator = null
            session.tcpOwner = null
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
        executor.shutdownNow()
        super.onDestroy()
    }
}
