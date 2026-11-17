package com.firewall.dns.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import java.net.Inet6Address

/** DNS nativos de la red física activa (Wi-Fi o datos móviles). */
object NetworkDns {
    const val EMERGENCY_DNS = "1.1.1.1"
    private val OWN_DNS = setOf("10.111.222.3", "fd66:f83a:c650::3")

    fun fromLink(lp: LinkProperties?, allowIpv6: Boolean = true): String =
        lp?.dnsServers.orEmpty()
            .filter { !it.isLoopbackAddress && !it.isAnyLocalAddress && !(it is Inet6Address && (!allowIpv6 || it.isLinkLocalAddress)) }
            .mapNotNull { it.hostAddress?.substringBefore('%') }
            .filter { it !in OWN_DNS }
            .distinct()
            .joinToString(",")

    fun active(context: Context, allowIpv6: Boolean = true): String = try {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        fromLink(cm.getLinkProperties(cm.activeNetwork), allowIpv6)
    } catch (_: Throwable) {
        ""
    }

    fun firstActiveDns(context: Context): String =
        active(context, allowIpv6 = false).substringBefore(',').ifEmpty { EMERGENCY_DNS }
}
