package com.firewall.dns.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import java.net.Inet6Address
import java.net.InetAddress

/** DNS nativos de la red física activa (Wi-Fi o datos móviles). */
object NetworkDns {
    const val EMERGENCY_DNS = "1.1.1.1"
    private val OWN_DNS = setOf("10.111.222.3", "fd66:f83a:c650::3", "10.10.10.1", "fd00:10:10::1")

    private fun isUsableDns(addr: InetAddress, allowIpv6: Boolean): Boolean {
        if (addr.isLoopbackAddress || addr.isAnyLocalAddress) return false
        if (addr is Inet6Address) {
            if (!allowIpv6 || addr.isLinkLocalAddress || addr.isSiteLocalAddress) return false
            val firstByte = addr.address[0].toInt() and 0xFE
            if (firstByte == 0xFC) return false // Excluye IPv6 ULA privada (fc00::/7)
        }
        return true
    }

    fun fromLink(lp: LinkProperties?, allowIpv6: Boolean = true): String =
        lp?.dnsServers.orEmpty()
            .filter { isUsableDns(it, allowIpv6) }
            .mapNotNull { it.hostAddress?.substringBefore('%') }
            .filter { it !in OWN_DNS }
            .distinct()
            .joinToString(",")

    @Suppress("DEPRECATION")
    fun active(context: Context, allowIpv6: Boolean = true): String = try {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val active = cm.activeNetwork
        val activeCaps = active?.let { cm.getNetworkCapabilities(it) }
        val physicalNet = if (active != null && activeCaps != null &&
            activeCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            !activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        ) {
            active
        } else {
            cm.allNetworks.firstOrNull { net ->
                cm.getNetworkCapabilities(net)?.let { c ->
                    c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        !c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                } == true
            }
        }
        fromLink(physicalNet?.let { cm.getLinkProperties(it) }, allowIpv6)
    } catch (_: Throwable) {
        ""
    }

    fun firstActiveDns(context: Context): String =
        active(context, allowIpv6 = false).substringBefore(',').ifEmpty { EMERGENCY_DNS }

    /** Tipo de conexión física con Internet; se ignora la interfaz TUN de la propia VPN. */
    @Suppress("DEPRECATION")
    fun currentType(context: Context): String = try {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val caps = cm.allNetworks.mapNotNull { cm.getNetworkCapabilities(it) }.filter {
            it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }
        when {
            caps.isEmpty() -> "Sin red"
            caps.any { it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) } -> "Wi-Fi"
            caps.any { it.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) } -> "Ethernet"
            caps.any { it.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) } -> "Datos móviles"
            else -> "Otra red"
        }
    } catch (_: Throwable) {
        "Sin red"
    }
}
