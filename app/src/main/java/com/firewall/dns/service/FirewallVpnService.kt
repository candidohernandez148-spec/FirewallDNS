package com.firewall.dns.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.celzero.firestack.backend.Backend
import com.celzero.firestack.intra.Intra
import com.celzero.firestack.intra.Tunnel
import com.celzero.firestack.settings.Settings
import com.firewall.dns.MainActivity

/** VPN basada en Firestack: filtra DNS con DomainBlocker y conexiones por UID con AppFirewallManager. */
class FirewallVpnService : VpnService() {

    private var tunnel: Tunnel? = null
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            stopSelf()
            return START_NOT_STICKY
        }
        startForegroundNotification()
        if (tunnel == null && !startTunnel()) {
            stopTunnel()
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    @Synchronized
    private fun startTunnel(): Boolean {
        return try {
            val builder = Builder()
                .setSession("FirewallDNS")
                .setMtu(MTU)
                .addAddress(GATEWAY4, 24)
                .addAddress(GATEWAY6, 120)
                .addDnsServer(DNS4)
                .addDnsServer(DNS6)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
            try {
                builder.addDisallowedApplication(packageName)
            } catch (_: PackageManager.NameNotFoundException) {}

            val established = builder.establish() ?: return false
            vpnInterface = established
            // Firestack se queda con el descriptor y lo cierra al desconectar.
            val tunFd = established.dup().detachFd().toLong()
            val bridge = FirestackBridge(this)
            val defaultDns = Intra.newDefaultDNS(Backend.DNS53, "1.1.1.1", "")
            val t = try {
                Intra.connect(
                    tunFd, MTU.toLong(), MTU.toLong(),
                    "$GATEWAY4/24,$GATEWAY6/120", "$DNS4:53,[$DNS6]:53",
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
            true
        } catch (_: Throwable) {
            false
        }
    }

    @Synchronized
    private fun stopTunnel() {
        val t = tunnel
        val fd = vpnInterface
        tunnel = null
        vpnInterface = null
        try { t?.disconnect() } catch (_: Throwable) {}
        try { fd?.close() } catch (_: Throwable) {}
    }

    override fun onRevoke() {
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
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
