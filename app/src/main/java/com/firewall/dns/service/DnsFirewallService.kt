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
import com.firewalldns.engine.android.AndroidEngineRuntime
import com.firewalldns.engine.dns.DnsEvaluation
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
import java.util.concurrent.atomic.AtomicLong

class DnsFirewallService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunReaderThread: Thread? = null
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
    @Volatile private var sharedUpstream: DnsUpstreamFailoverClient? = null

    companion object {
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

        private val TRAPPED_IPV4_DNS = listOf("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1")
        private val TRAPPED_IPV6_DNS = listOf(
            "2001:4860:4860::8888", "2001:4860:4860::8844",
            "2606:4700:4700::1111", "2606:4700:4700::1001"
        )
    }

    override fun onCreate() {
        super.onCreate()
        FirewallRepository.init(applicationContext)
        connectivityManager = getSystemService(ConnectivityManager::class.java)

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

    private fun startVpn() = synchronized(vpnLock) {
        closeInterfaceSync()
        val upstream = FirewallRepository.getUpstreamDns()
        val builder = Builder()
            .setSession("FirewallDNS")
            .addAddress("10.10.10.2", 32)
            .addDnsServer("10.10.10.1")
            .addRoute("10.10.10.1", 32)
            .addAddress("fd00:10:10::2", 128)
            .addDnsServer("fd00:10:10::1")
            .addRoute("fd00:10:10::1", 128)
        TRAPPED_IPV4_DNS.filter { it != upstream }.forEach { builder.addRoute(it, 32) }
        TRAPPED_IPV6_DNS.forEach { builder.addRoute(it, 128) }

        (FirewallRepository.excludedPackages.value + packageName).forEach { pkg ->
            try {
                builder.addDisallowedApplication(pkg)
            } catch (_: PackageManager.NameNotFoundException) {}
        }

        val established = builder.establish()
        if (established == null) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        vpnInterface = established
        installSharedEngine()
        isRunning = true
        FirewallRepository.setRunning(true, "FirewallDNS TUN (DNS)")
        val input = FileInputStream(established.fileDescriptor)
        val output = FileOutputStream(established.fileDescriptor)

        tunReaderThread = Thread {
            val buffer = ByteArray(4096)
            try {
                while (isRunning && !Thread.interrupted()) {
                    val length = input.read(buffer)
                    if (length < 0) break
                    if (length > 0) {
                        val copy = buffer.copyOf(length)
                        try {
                            executor.execute {
                                try {
                                    handlePacket(copy, output)
                                } catch (_: Exception) {
                                    packetProcessingErrors.incrementAndGet()
                                }
                            }
                        } catch (_: RejectedExecutionException) {
                            // No ejecutar handlePacket en el lector: puede esperar al DNS upstream.
                            queueRejectedPackets.incrementAndGet()
                        }
                    }
                }
            } catch (_: IOException) {}
        }.apply { start() }
    }

    private fun handlePacket(req: ByteArray, output: FileOutputStream) {
        if (req.isEmpty()) return
        val version = (req[0].toInt() ushr 4) and 0x0F
        val isIpv6: Boolean
        val ipHeaderLen: Int
        val protocol: Int
        val srcIp: ByteArray
        val dstIp: ByteArray

        when (version) {
            4 -> {
                if (req.size < 20) return
                isIpv6 = false
                ipHeaderLen = (req[0].toInt() and 0x0F) * 4
                if (ipHeaderLen < 20 || req.size < ipHeaderLen) return
                val fragmentField = DnsPacketEngine.readU16(req, 6)
                if ((fragmentField and 0x3FFF) != 0) return
                protocol = req[9].toInt() and 0xFF
                srcIp = req.copyOfRange(12, 16)
                dstIp = req.copyOfRange(16, 20)
            }
            6 -> {
                if (req.size < 40) return
                isIpv6 = true
                ipHeaderLen = 40
                protocol = req[6].toInt() and 0xFF
                if (protocol != 17 && protocol != 6) return
                srcIp = req.copyOfRange(8, 24)
                dstIp = req.copyOfRange(24, 40)
            }
            else -> return
        }

        if (protocol == 6) {
            if (req.size < ipHeaderLen + 20) return
            val tcpDestinationPort = DnsPacketEngine.readU16(req, ipHeaderLen + 2)
            if (tcpDestinationPort == 53) {
                DnsPacketEngine.buildTcpRstResponse(req, isIpv6, ipHeaderLen, srcIp, dstIp)?.let {
                    writePacket(output, it)
                }
            }
            return
        }

        if (protocol != 17 || req.size < ipHeaderLen + 8) return
        val srcPort = DnsPacketEngine.readU16(req, ipHeaderLen)
        val dstPort = DnsPacketEngine.readU16(req, ipHeaderLen + 2)
        val udpLength = DnsPacketEngine.readU16(req, ipHeaderLen + 4)
        if (dstPort != 53 || udpLength < 8 || ipHeaderLen + udpLength > req.size) return

        val dnsPayload = req.copyOfRange(ipHeaderLen + 8, ipHeaderLen + udpLength)
        val query = DnsPacketEngine.parseDnsQuery(dnsPayload) ?: return
        val appUid = resolveAppUid(srcIp, srcPort, dstIp, dstPort)
        val appName = resolveAppName(appUid)
        val appPackage = resolvePackageName(appUid)
        val evaluation = sharedEngine?.engine?.evaluateDns(dnsPayload, appPackage)
        val engineDecision = when (evaluation) {
            is DnsEvaluation.Blocked -> true to evaluation.decision.reason
            is DnsEvaluation.Forward -> false to evaluation.decision.reason
            is DnsEvaluation.Rejected -> return
            null -> FirewallRepository.evaluateDomain(query.domain)
        }
        val appBlocked = appUid >= 0 && AppFirewallManager.isUidBlocked(appUid)
        val observationMode = FirewallRepository.isObservationModeEnabled()
        val policyWouldBlock = appBlocked || engineDecision.first
        val shouldBlock = policyWouldBlock && !observationMode
        val ruleReason = if (appBlocked) "DNS bloqueado para la aplicación" else engineDecision.second
        val finalReason = when {
            observationMode && policyWouldBlock -> "OBSERVE: $ruleReason"
            observationMode -> "OBSERVE: permitido"
            else -> ruleReason
        }

        val dnsResponse: ByteArray?
        if (shouldBlock) {
            dnsResponse = DnsPacketEngine.buildNxDomainResponse(dnsPayload, query.questionEndOffset)
        } else {
            val cacheKey = "${query.domain.lowercase()}:${query.qType}:${FirewallRepository.getUpstreamDns()}"
            val now = System.currentTimeMillis()
            val cached = dnsCache[cacheKey]?.takeIf { it.expiresAt > now }
            val cachedResponse = cached?.response?.copyOf()?.apply {
                this[0] = dnsPayload[0]
                this[1] = dnsPayload[1]
            }?.takeIf { DnsPacketEngine.matchesDnsResponse(dnsPayload, it) }
            if (cachedResponse != null) {
                dnsResponse = cachedResponse
            } else {
                dnsResponse = sharedUpstream?.let { upstream ->
                    when (val result = upstream.exchange(dnsPayload)) {
                        is DnsUpstreamResult.Success -> result.response.message
                        is DnsUpstreamResult.Failure, DnsUpstreamResult.Cancelled -> null
                    }
                } ?: forwardDnsQuery(dnsPayload)
                if (dnsResponse != null) {
                    if (dnsCache.size > 600) dnsCache.clear()
                    dnsCache[cacheKey] = CachedDns(dnsResponse, now + CACHE_TTL_MS)
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
            val responsePacket = if (isIpv6) {
                DnsPacketEngine.buildIpv6UdpResponse(srcIp, dstIp, srcPort, dstPort, dnsResponse)
            } else {
                DnsPacketEngine.buildIpv4UdpResponse(req, srcIp, dstIp, srcPort, dstPort, dnsResponse)
            }
            writePacket(output, responsePacket)
        }
    }

    private fun writePacket(output: FileOutputStream, data: ByteArray) {
        synchronized(writeLock) {
            try { output.write(data) } catch (_: IOException) {}
        }
    }

    private fun resolveAppUid(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return Process.INVALID_UID
        return try {
            connectivityManager.getConnectionOwnerUid(
                OsConstants.IPPROTO_UDP,
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
            sharedUpstream = null
            return
        }
        val runtime = runCatching {
            AndroidEngineRuntime(this, FirewallRepository.isSmartModeEnabled()).also {
                it.engine.replaceRules(FirewallRepository.enginePolicyRules())
            }
        }.getOrNull()
        sharedEngine = runtime
        sharedUpstream = runtime?.let { engine ->
            runCatching {
                engine.createDnsFailover(listOf(DnsUpstreamConfig(FirewallRepository.getUpstreamDns(), timeoutMillis = 2_000)))
            }.getOrNull()
        }
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

    private fun forwardDnsQuery(dnsPayload: ByteArray): ByteArray? {
        var socket: DatagramSocket? = null
        return try {
            socket = DatagramSocket()
            socket.soTimeout = 3500
            if (!protect(socket)) return null
            val addr = InetAddress.getByName(FirewallRepository.getUpstreamDns())
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
        isRunning = false
        FirewallRepository.setRunning(false)
        tunReaderThread?.interrupt()
        tunReaderThread = null
        sharedEngine = null
        sharedUpstream = null
        val iface = vpnInterface
        try { iface?.close() } catch (_: IOException) {}
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
        serviceScope.cancel()
        isRunning = false
        Thread {
            synchronized(vpnLock) { closeInterfaceSync() }
        }.start()
        executor.shutdownNow()
        super.onDestroy()
    }
}
