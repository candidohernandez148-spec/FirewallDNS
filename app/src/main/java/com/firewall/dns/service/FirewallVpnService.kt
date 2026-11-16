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

    override fun onCreate() {
        super.onCreate()
        FirewallRepository.init(applicationContext)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            FirewallRepository.setShouldRun(false)
            shutdown()
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
        return START_STICKY
    }

    private fun startTunnel(): Boolean = synchronized(lock) {
        if (stopRequested) return false
        try {
            // Sin IPv6 real, enrutar ::/0 provoca timeouts y lentitud.
            val v6 = hasIpv6()
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

            val established = builder.establish() ?: return false
            vpnInterface = established
            // Firestack se queda con el descriptor y lo cierra al desconectar.
            val tunFd = established.dup().detachFd().toLong()
            val bridge = FirestackBridge(this)
            val defaultDns = Intra.newDefaultDNS(Backend.DNS53, "1.1.1.1", "")
            val t = try {
                Intra.connect(
                    tunFd, MTU.toLong(), MTU.toLong(),
                    if (v6) "$GATEWAY4/24,$GATEWAY6/120" else "$GATEWAY4/24",
                    if (v6) "$DNS4:53,[$DNS6]:53" else "$DNS4:53",
                    defaultDns, bridge
                )
            } catch (e: Throwable) {
                try { ParcelFileDescriptor.adoptFd(tunFd.toInt()).close() } catch (_: Throwable) {}
                throw e
            }
            Settings.setTunMode(Settings.DNSModeIP, Settings.BlockModeFilter, Settings.PtModeAuto)
            try {
                Intra.addDoHTransport(t, Backend.Preferred, DOH_URL, DOH_IPS)
                bridge.upstreamId = Backend.Preferred
            } catch (_: Throwable) {
                bridge.upstreamId = Backend.Default
            }
            tunnel = t
            FirewallRepository.setShouldRun(true)
            FirewallRepository.setRunning(true, "Firestack")
            true
        } catch (_: Throwable) {
            false
        }
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

    // Cierre ordenado: Firestack primero, después el descriptor de la VPN, y por último el servicio.
    private fun shutdown() {
        stopRequested = true
        FirewallRepository.setRunning(false)
        ioScope.launch {
            synchronized(lock) {
                try {
                    tunnel?.disconnect()
                    vpnInterface?.close()
                } catch (_: Throwable) {
                } finally {
                    tunnel = null
                    vpnInterface = null
                }
            }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onRevoke() {
        FirewallRepository.setShouldRun(false)
        shutdown()
        super.onRevoke()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun startForegroundNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "Firewall VPN", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Firewall DNS activo")
            .setContentText("Filtrado de dominios y apps con Firestack")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
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
        const val ACTION_STOP = "com.firewall.dns.vpn.STOP"
        private const val CHANNEL_ID = "firewall_vpn_channel"
        private const val NOTIFICATION_ID = 2002
        private const val MTU = 1500
        private const val GATEWAY4 = "10.111.222.1"
        private const val DNS4 = "10.111.222.3"
        private const val GATEWAY6 = "fd66:f83a:c650::1"
        private const val DNS6 = "fd66:f83a:c650::3"
        private const val DOH_URL = "https://cloudflare-dns.com/dns-query"
        private const val DOH_IPS = "1.1.1.1,1.0.0.1,2606:4700:4700::1111"

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
