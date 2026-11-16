package com.firewall.dns.domain.engine

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

object AppFirewallManager {

    private val blockedUids = ConcurrentHashMap<Int, Boolean>()

    fun setBlocked(uid: Int, blocked: Boolean) {
        if (blocked) blockedUids[uid] = true else blockedUids.remove(uid)
    }

    fun isUidBlocked(uid: Int): Boolean = blockedUids[uid] == true

    fun blockedUidSet(): Set<Int> = blockedUids.keys.toSet()

    fun clear() = blockedUids.clear()

    fun isConnectionBlocked(
        context: Context,
        protocol: Int,
        srcIp: String,
        srcPort: Int,
        dstIp: String,
        dstPort: Int
    ): Boolean {
        val uid = getUidForConnection(context, protocol, srcIp, srcPort, dstIp, dstPort)
        return uid != Process.INVALID_UID && isUidBlocked(uid)
    }

    // protocol: IPPROTO_TCP (6) o IPPROTO_UDP (17). Devuelve Process.INVALID_UID si no se puede resolver.
    fun getUidForConnection(
        context: Context,
        protocol: Int,
        srcIp: String,
        srcPort: Int,
        dstIp: String,
        dstPort: Int
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return Process.INVALID_UID
        return try {
            val cm = context.getSystemService(ConnectivityManager::class.java)
                ?: return Process.INVALID_UID
            val local = InetSocketAddress(InetAddress.getByName(srcIp), srcPort)
            val remote = InetSocketAddress(InetAddress.getByName(dstIp), dstPort)
            cm.getConnectionOwnerUid(protocol, local, remote)
        } catch (_: Exception) {
            Process.INVALID_UID
        }
    }
}
