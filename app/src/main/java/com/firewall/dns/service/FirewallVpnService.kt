package com.firewall.dns.service

import android.app.NotificationChannel
import com.firewall.dns.R
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
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
import com.firewall.dns.data.repository.FirewallRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** VPN basada en Firestack: filtra DNS con DomainBlocker y conexiones por UID con AppFirewallManager. */
class FirewallVpnService : VpnService() {

    @Volatile
    private var stopRequested = false
    private val lock = Any()
    // Alcance propio, no cancelado en onDestroy, para que el cierre nativo termine aunque el servicio muera.
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunnel: Tunnel? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile
    private var lastDnsIps = ""

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "onCreate")
        FirewallRepository.init(applicationContext)
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
        startForegroundNotification()
        if (tunnel == null) {
            // Firestack puede tardar en conectar; se hace fuera del hilo principal para no congelar la app.
            Thread {
                if (!startTunnel() && !stopRequested) {
                    // Si Firestack no arranca, se usa el filtro DNS clásico para no dejar al usuario sin protección.
                    shutdown()
                    ContextCompat.startForegroundService(
                        this,
                        Intent(this, DnsFirewallService::class.java).apply { action = DnsFirewallService.ACTION_START }
                    )
                }
            }.start()
        }
        return START_NOT_STICKY
    }

    private fun startTunnel(): Boolean = synchronized(lock) {
        if (stopRequested) return false
        Log.d(TAG, "startTunnel: inicio")
        try {
            // Sin IPv6 real, enrutar ::/0 provoca timeouts y lentitud.
            val v6 = hasIpv6()
            // Debe leerse antes de establish(): después la red activa pasa a ser la propia VPN.
            val cm = getSystemService(ConnectivityManager::class.java)
            val activeDnsIps = getActiveNetworkDns(v6)
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

            cm.activeNetwork?.let { builder.setUnderlyingNetworks(arrayOf(it)) }

            val established = builder.establish() ?: return false
            vpnInterface = established
            Log.d(TAG, "startTunnel: establish() ok")
            val bridge = FirestackBridge(this)
            Log.d(TAG, "DNS de la red activa: $activeDnsIps")
            val defaultDns = Intra.newDefaultDNS(Backend.DNS53, activeDnsIps, "")
            // vpnInterface se mantiene abierto y solo se cierra en closeResources(), después de disconnect().
            // dupTunFd(true): Firestack trabaja con su propia copia del descriptor y nosotros conservamos el original.
            // Con false, Firestack lo cierra al desconectar y nuestro close() sería un doble cierre del mismo fd.
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
            registerNetworkMonitor()
            FirewallRepository.setShouldRun(true)
            FirewallRepository.setRunning(true, "Firestack")
            Log.d(TAG, "startTunnel: protección activa")
            true
        } catch (e: Throwable) {
            Log.e(TAG, "startTunnel: falló", e)
            FirewallRepository.addLog("firestack", "-", false, "Firestack falló (${e.javaClass.simpleName}: ${e.message}); se usa el respaldo DNS", "Sistema")
            closeResources()
            false
        }
    }

    // Si la red no informa DNS, 1.1.1.1 se usa solo como último recurso.
    private fun getActiveNetworkDns(allowIpv6: Boolean = true): String =
        NetworkDns.active(this, allowIpv6).ifEmpty { NetworkDns.EMERGENCY_DNS }

    private fun registerNetworkMonitor() {
        if (networkCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java)
        // Solo redes físicas: si se observara la propia VPN, sus DNS apuntarían a nuestro túnel.
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                setUnderlyingNetworks(arrayOf(network))
                applyNetworkDns(cm.getLinkProperties(network))
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: android.net.LinkProperties) {
                applyNetworkDns(linkProperties)
            }

            override fun onLost(network: Network) {
                val other = cm.allNetworks.firstOrNull {
                    it != network && cm.getNetworkCapabilities(it)?.let { c ->
                        c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && !c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    } == true
                }
                setUnderlyingNetworks(other?.let { arrayOf(it) })
                if (other != null) applyNetworkDns(cm.getLinkProperties(other))
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
    private fun applyNetworkDns(lp: android.net.LinkProperties?) {
        val t = tunnel ?: return
        val ips = NetworkDns.fromLink(lp, hasIpv6())
        if (ips.isBlank()) {
            Log.w(TAG, "La red no informó DNS; se conservan los actuales")
            return
        }
        if (ips == lastDnsIps) return
        lastDnsIps = ips
        Log.d(TAG, "DNS de la red cambió: $ips")
        try { Intra.setSystemDNS(t, ips) } catch (e: Throwable) { Log.e(TAG, "setSystemDNS falló", e) }
        try { Intra.addDefaultTransport(t, Backend.DNS53, ips, "") } catch (e: Throwable) { Log.e(TAG, "addDefaultTransport falló", e) }
    }

    private fun unregisterNetworkMonitor() {
        val callback = networkCallback ?: return
        networkCallback = null
        try {
            getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback)
        } catch (_: Throwable) {}
    }

    private fun hasIpv6(): Boolean = try {
        val cm = getSystemService(ConnectivityManager::class.java)
        cm.getLinkProperties(cm.activeNetwork)?.linkAddresses?.any {
            val a = it.address
            a is java.net.Inet6Address && !a.isLinkLocalAddress && !a.isLoopbackAddress && !a.isSiteLocalAddress
        } == true
    } catch (_: Throwable) {
        false
    }

    // Cierre ordenado: disconnect de Firestack, cerrar el descriptor de la VPN (obligatorio para quitar la llave) y detener el servicio.
    private fun shutdown() {
        stopRequested = true
        Log.d(TAG, "shutdown: inicio")
        ioScope.launch {
            closeResources()
            // La UI se actualiza solo cuando el túnel ya está cerrado.
            FirewallRepository.setRunning(false)
            Log.d(TAG, "shutdown: stopForeground + stopSelf")
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (e: Throwable) { Log.d(TAG, "stopForeground falló", e) }
            stopSelf()
        }
    }

    private fun closeResources() = synchronized(lock) {
        unregisterNetworkMonitor()
        lastDnsIps = ""
        val t = tunnel
        if (t != null) {
            // disconnect() es nativo y puede bloquearse; con tiempo máximo para no dejar el servicio colgado.
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

    override fun onRevoke() {
        Log.d(TAG, "onRevoke")
        FirewallRepository.setShouldRun(false)
        shutdown()
        super.onRevoke()
    }

    override fun onDestroy() {
        Log.d(TAG, "onDestroy")
        stopRequested = true
        // Limpieza síncrona y segura para no dejar el túnel abierto; fuera del hilo principal si hay bloqueo.
        ioScope.launch {
            closeResources()
            FirewallRepository.setRunning(false)
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
