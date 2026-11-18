package com.firewall.dns.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.celzero.firestack.backend.Backend
import com.celzero.firestack.intra.Intra
import com.celzero.firestack.intra.Tunnel
import com.celzero.firestack.settings.Settings
import com.firewall.dns.MainActivity
import com.firewall.dns.R
import com.firewall.dns.data.repository.FirewallRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.net.Inet6Address
import java.util.concurrent.atomic.AtomicBoolean

/** VPN basada en Firestack: filtra DNS con DomainBlocker y conexiones por UID con AppFirewallManager. */
class FirewallVpnService : VpnService() {

    @Volatile
    private var stopRequested = false

    @Volatile
    private var fallingBack = false

    @Volatile
    private var tunnel: Tunnel? = null

    @Volatile
    private var lastDnsIps = ""

    private val isStarting = AtomicBoolean(false)
    private val lock = Any()

    // Alcance propio, no cancelado en onDestroy, para que el cierre nativo termine aunque el servicio muera.
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "onCreate")
        FirewallRepository.init(applicationContext)
        ioScope.launch {
            FirewallRepository.closeUidConnectionsEvent.collect { uid ->
                val activeTunnel = tunnel ?: return@collect
                runCatching { activeTunnel.closeConns(uid.toString()) }
                    .onFailure { error ->
                        Log.w(TAG, "No se pudieron cerrar conexiones del UID $uid", error)
                    }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand action=${intent?.action} intent=${intent != null}")
        if (intent?.action == ACTION_STOP) {
            Log.d(TAG, "ACTION_STOP recibido")
            FirewallRepository.setShouldRun(false)
            shutdown()
            return START_NOT_STICKY
        }
        if (intent == null) {
            // Reinicio del sistema sin intent: no se vuelve a encender la VPN.
            Log.d(TAG, "intent == null, no se reinicia la VPN")
            FirewallRepository.setShouldRun(false)
            stopSelf()
            return START_NOT_STICKY
        }

        stopRequested = false
        fallingBack = false
        startForegroundNotification()

        if (tunnel == null && isStarting.compareAndSet(false, true)) {
            ioScope.launch {
                try {
                    // Igual que MainActivity: ni Firestack ni el respaldo arrancan
                    // con reglas locales aún sin cargar.
                    FirewallRepository.awaitInitialBlocklistLoad()
                    if (stopRequested) return@launch
                    val started = startTunnel()
                    if (!started && !stopRequested) {
                        fallingBack = true
                        closeResources()
                        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
                        stopSelf()
                        ContextCompat.startForegroundService(
                            this@FirewallVpnService,
                            Intent(this@FirewallVpnService, DnsFirewallService::class.java).apply {
                                action = DnsFirewallService.ACTION_START
                            }
                        )
                    }
                } finally {
                    isStarting.set(false)
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun startTunnel(): Boolean = synchronized(lock) {
        if (stopRequested) return false
        if (tunnel != null) return true
        Log.d(TAG, "startTunnel: inicio")
        try {
            val cm = getSystemService(ConnectivityManager::class.java)
            val activeNet = cm.activeNetwork
            val activeLp = cm.getLinkProperties(activeNet)
            val v6 = hasGlobalIpv6(activeLp)
            val dnsProbe = getActiveNetworkDns(v6)
            val activeDnsIps = dnsProbe.orderedServers.ifEmpty { NetworkDns.EMERGENCY_DNS }
            Log.i(TAG, "Medición de DNS de la red activa: ${dnsProbe.measurements}; orden: $activeDnsIps")

            val builder = Builder()
                .setSession("FirewallDNS")
                .setMtu(MTU)
                .addAddress(GATEWAY4, 24)
                .addDnsServer(DNS4)
                .addRoute("0.0.0.0", 0)
            if (v6) {
                builder.addAddress(GATEWAY6, 120)
                    .addDnsServer(DNS6)
                    .addRoute("::", 0)
            }
            (FirewallRepository.excludedPackages.value + packageName).forEach { pkg ->
                try {
                    builder.addDisallowedApplication(pkg)
                } catch (_: PackageManager.NameNotFoundException) {}
            }

            activeNet?.let { builder.setUnderlyingNetworks(arrayOf(it)) }

            val established = builder.establish() ?: return false
            vpnInterface = established
            Log.d(TAG, "startTunnel: establish() ok")

            val bridge = FirestackBridge(this)
            Log.d(TAG, "DNS de la red activa: $activeDnsIps")
            val defaultDns = Intra.newDefaultDNS(Backend.DNS53, activeDnsIps, "")

            Settings.dupTunFd(true)
            Settings.setTunMode(Settings.DNSModeIP, Settings.BlockModeFilter, Settings.PtModeAuto)
            val t = Intra.connect(
                established.fd.toLong(), MTU.toLong(), MTU.toLong(),
                if (v6) "$GATEWAY4/24,$GATEWAY6/120" else "$GATEWAY4/24",
                if (v6) "$DNS4:53,[$DNS6]:53" else "$DNS4:53",
                defaultDns, bridge
            )
            Log.d(TAG, "startTunnel: Intra.connect ok")
            tunnel = t
            lastDnsIps = activeDnsIps
            registerNetworkMonitor()
            FirewallRepository.setShouldRun(true)
            FirewallRepository.setRunning(true, "Firestack")
            Log.d(TAG, "startTunnel: protección activa")
            true
        } catch (e: Throwable) {
            Log.e(TAG, "startTunnel: falló", e)
            FirewallRepository.addLog(
                "firestack", "-", false,
                "Firestack falló (${e.javaClass.simpleName}: ${e.message}); se usa el respaldo DNS",
                "Sistema"
            )
            closeResources()
            false
        }
    }

    private fun getActiveNetworkDns(allowIpv6: Boolean = true): NetworkDns.DnsProbeResult {
        val candidates = NetworkDns.active(this, allowIpv6).ifEmpty { NetworkDns.EMERGENCY_DNS }
        return NetworkDns.rankByLatency(this, candidates)
    }

    private fun registerNetworkMonitor() {
        if (networkCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java)
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (stopRequested || tunnel == null) return
                try { setUnderlyingNetworks(arrayOf(network)) } catch (_: Throwable) {}
                val linkProperties = cm.getLinkProperties(network)
                ioScope.launch { applyNetworkDns(linkProperties) }
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                if (stopRequested || tunnel == null) return
                ioScope.launch { applyNetworkDns(linkProperties) }
            }

            override fun onLost(network: Network) {
                if (stopRequested || tunnel == null) return
                val other = cm.allNetworks.firstOrNull {
                    it != network && cm.getNetworkCapabilities(it)?.let { c ->
                        c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                            !c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    } == true
                }
                try { setUnderlyingNetworks(other?.let { arrayOf(it) }) } catch (_: Throwable) {}
                if (other != null) {
                    val linkProperties = cm.getLinkProperties(other)
                    ioScope.launch { applyNetworkDns(linkProperties) }
                }
            }
        }
        try {
            cm.registerNetworkCallback(request, callback)
            networkCallback = callback
        } catch (e: Throwable) {
            Log.d(TAG, "registerNetworkMonitor falló", e)
        }
    }

    // Al cambiar de Wi-Fi a datos (o al revés) Firestack pasa a usar los DNS de la nueva red.
    private fun applyNetworkDns(lp: LinkProperties?) {
        synchronized(lock) {
            if (stopRequested) return
            val t = tunnel ?: return
            val candidates = NetworkDns.fromLink(lp, hasGlobalIpv6(lp))
            if (candidates.isBlank()) {
                Log.w(TAG, "La red no informó DNS; se conservan los actuales")
                return
            }
            val probe = NetworkDns.rankByLatency(this, candidates)
            val ips = probe.orderedServers.ifEmpty { candidates }
            Log.i(TAG, "Medición DNS al cambiar de red: ${probe.measurements}; orden: $ips")
            if (ips == lastDnsIps) return
            Log.d(TAG, "Aplicando DNS de la nueva red: $ips")
            try {
                // Solo confirmar el estado después de aplicar ambas operaciones nativas.
                // Si cualquiera falla, la siguiente notificación de red podrá reintentarlo.
                Intra.setSystemDNS(t, ips)
                Intra.addDefaultTransport(t, Backend.DNS53, ips, "")
                lastDnsIps = ips
                Log.i(TAG, "DNS de la nueva red aplicados correctamente: $ips")
            } catch (e: Throwable) {
                Log.e(TAG, "No se pudieron aplicar los DNS de la nueva red; se reintentará", e)
            }
        }
    }

    private fun unregisterNetworkMonitor() {
        val callback = networkCallback ?: return
        networkCallback = null
        try {
            getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback)
        } catch (_: Throwable) {}
    }

    private fun hasGlobalIpv6(lp: LinkProperties?): Boolean = try {
        lp?.linkAddresses?.any {
            val a = it.address
            a is Inet6Address &&
                !a.isLinkLocalAddress &&
                !a.isLoopbackAddress &&
                !a.isSiteLocalAddress &&
                (a.address[0].toInt() and 0xFE) != 0xFC
        } == true
    } catch (_: Throwable) {
        false
    }

    private fun shutdown() {
        stopRequested = true
        Log.d(TAG, "shutdown: inicio")
        ioScope.launch {
            closeResources()
            if (!fallingBack) FirewallRepository.setRunning(false)
            Log.d(TAG, "shutdown: stopForeground + stopSelf")
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (e: Throwable) { Log.d(TAG, "stopForeground falló", e) }
            stopSelf()
        }
    }

    private fun closeResources() {
        synchronized(lock) {
            unregisterNetworkMonitor()
            lastDnsIps = ""
            val t = tunnel
            if (t != null) {
                val worker = Thread {
                    try {
                        Log.d(TAG, "tunnel.disconnect()")
                        t.disconnect()
                    } catch (e: Throwable) {
                        Log.d(TAG, "tunnel.disconnect() falló", e)
                    }
                }
                worker.start()
                worker.join(DISCONNECT_TIMEOUT_MS)
                if (worker.isAlive) Log.w(TAG, "tunnel.disconnect() excedió ${DISCONNECT_TIMEOUT_MS}ms; se cierra el descriptor igualmente")
            }
            tunnel = null
            try {
                Log.d(TAG, "tunFd.close()")
                vpnInterface?.close()
            } catch (e: Throwable) {
                Log.d(TAG, "tunFd.close() falló", e)
            }
            vpnInterface = null
        }
    }

    override fun onRevoke() {
        Log.d(TAG, "onRevoke")
        FirewallRepository.setShouldRun(false)
        shutdown()
        super.onRevoke()
    }

    override fun onDestroy() {
        Log.d(TAG, "onDestroy")
        stopRequested = true
        val wasFallback = fallingBack
        ioScope.launch {
            try {
                closeResources()
                if (!wasFallback) FirewallRepository.setRunning(false)
            } finally {
                // This service owns a long-lived event collector. Release it only after
                // native tunnel teardown has completed, otherwise each restart leaks a collector.
                ioScope.cancel()
            }
        }
        super.onDestroy()
    }

    private fun startForegroundNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "Firewall VPN", NotificationManager.IMPORTANCE_LOW).apply { setShowBadge(false) }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Firewall DNS activo")
            .setContentText("Filtrado de dominios y apps con Firestack")
            .setSmallIcon(R.drawable.ic_stat_firewall)
            .setNumber(0)
            .setBadgeIconType(NotificationCompat.BADGE_ICON_NONE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
            )
            .setOngoing(true)
            .build()
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else 0
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, type)
    }

    companion object {
        private const val TAG = "FirewallVpnService"
        const val ACTION_STOP = "com.firewall.dns.vpn.STOP"
        private const val CHANNEL_ID = "firewall_vpn_channel"
        private const val NOTIFICATION_ID = 2002
        private const val MTU = 1500
        private const val DISCONNECT_TIMEOUT_MS = 3000L
        private const val GATEWAY4 = "10.111.222.1"
        private const val DNS4 = "10.111.222.3"
        private const val GATEWAY6 = "fd66:f83a:c650::1"
        private const val DNS6 = "fd66:f83a:c650::3"

        fun start(context: Context) {
            context.startForegroundService(Intent(context, FirewallVpnService::class.java))
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, FirewallVpnService::class.java).apply { action = ACTION_STOP }
            )
        }
    }
}
