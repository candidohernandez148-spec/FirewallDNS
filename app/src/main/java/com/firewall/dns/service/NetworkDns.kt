package com.firewall.dns.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.VpnService
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** DNS nativos de la red física activa (Wi-Fi o datos móviles). */
object NetworkDns {
    const val EMERGENCY_DNS = "1.1.1.1"
    private val OWN_DNS = setOf("10.111.222.3", "fd66:f83a:c650::3", "10.10.10.1", "fd00:10:10::1")
    private const val PROBE_TIMEOUT_MS = 850
    private const val PROBE_BATCH_TIMEOUT_MS = 1000L
    private const val PROBE_NAME = "connectivitycheck.gstatic.com"
    private val probeId = AtomicInteger(0x4A20)

    data class DnsProbeResult(
        val orderedServers: String,
        val measurements: String
    )

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

    /**
     * Mide en paralelo el tiempo de respuesta DNS, protegiendo los sockets para que
     * las pruebas salgan por la red física y no vuelvan a entrar en la propia VPN.
     * Los servidores sin respuesta se conservan al final como respaldo; si ninguno
     * responde, se mantiene el orden original para no dejar al usuario sin DNS.
     */
    fun rankByLatency(vpn: VpnService, dnsCsv: String): DnsProbeResult {
        val servers = dnsCsv.split(',').map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        if (servers.isEmpty()) return DnsProbeResult("", "sin servidores DNS")
        val executor = Executors.newFixedThreadPool(servers.size.coerceAtMost(4))
        try {
            val futures = executor.invokeAll(
                servers.map { server -> Callable { server to probeLatency(vpn, server) } },
                PROBE_BATCH_TIMEOUT_MS,
                TimeUnit.MILLISECONDS
            )
            val measured = futures.mapIndexed { index, future ->
                if (future.isCancelled) servers[index] to null
                else try { future.get() } catch (_: Exception) { servers[index] to null }
            }
            val responsive = measured.filter { it.second != null }.sortedBy { it.second }
            val unresponsive = measured.filter { it.second == null }
            val ordered = if (responsive.isNotEmpty()) {
                (responsive + unresponsive).joinToString(",") { it.first }
            } else {
                servers.joinToString(",")
            }
            val details = measured.joinToString("; ") { (server, latency) ->
                if (latency == null) "$server: sin respuesta" else "$server: ${latency} ms"
            }
            return DnsProbeResult(ordered, details)
        } catch (_: Exception) {
            return DnsProbeResult(servers.joinToString(","), "medición no disponible")
        } finally {
            executor.shutdownNow()
        }
    }

    private fun probeLatency(vpn: VpnService, server: String): Long? {
        val id = probeId.getAndIncrement() and 0xFFFF
        val query = buildProbeQuery(id) ?: return null
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = PROBE_TIMEOUT_MS
                if (!vpn.protect(socket)) return null
                val address = InetAddress.getByName(server)
                val started = System.nanoTime()
                socket.send(DatagramPacket(query, query.size, address, 53))
                val buffer = ByteArray(512)
                val response = DatagramPacket(buffer, buffer.size)
                socket.receive(response)
                val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
                if (response.length < 12) return null
                val responseId = ((buffer[0].toInt() and 0xFF) shl 8) or (buffer[1].toInt() and 0xFF)
                val flags = ((buffer[2].toInt() and 0xFF) shl 8) or (buffer[3].toInt() and 0xFF)
                if (responseId != id || (flags and 0x8000) == 0 || (flags and 0x000F) == 2) null
                else elapsedMs
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun buildProbeQuery(id: Int): ByteArray? = try {
        val output = ByteArrayOutputStream()
        output.write(byteArrayOf(
            (id shr 8).toByte(), id.toByte(),
            0x01, 0x00, // standard query, recursion desired
            0x00, 0x01, // one question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ))
        PROBE_NAME.split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            output.write(bytes.size)
            output.write(bytes)
        }
        output.write(0)
        output.write(byteArrayOf(0x00, 0x01, 0x00, 0x01)) // A, IN
        output.toByteArray()
    } catch (_: Exception) {
        null
    }

    /**
     * Returns the same physical Network whose LinkProperties supply active DNS.
     * Keeping the Network handle prevents sockets from using a different default
     * route when Android exposes the VPN as the app's active network.
     */
    @Suppress("DEPRECATION")
    fun activeNetwork(context: Context): android.net.Network? = try {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val active = cm.activeNetwork
        val activeCaps = active?.let { cm.getNetworkCapabilities(it) }
        if (active != null && activeCaps != null &&
            activeCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            !activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        ) {
            active
        } else {
            cm.allNetworks
                .filter { network ->
                    cm.getNetworkCapabilities(network)?.let { caps ->
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                            !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    } == true
                }
                .sortedWith(
                    compareByDescending<android.net.Network> { network ->
                        cm.getNetworkCapabilities(network)?.hasCapability(
                            NetworkCapabilities.NET_CAPABILITY_VALIDATED
                        ) == true
                    }.thenBy { network ->
                        val caps = cm.getNetworkCapabilities(network)
                        when {
                            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> 0
                            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> 1
                            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> 2
                            else -> 3
                        }
                    }
                )
                .firstOrNull()
        }
    } catch (_: Throwable) {
        null
    }

    data class ActiveDnsSnapshot(
        val network: android.net.Network?,
        val resolvers: List<String>,
        val transport: String,
        val validated: Boolean,
    )

    /** Resolver addresses and Network identity are read from one network generation. */
    @Suppress("DEPRECATION")
    fun activeSnapshot(context: Context, allowIpv6: Boolean = true): ActiveDnsSnapshot = try {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val network = activeNetwork(context)
        val capabilities = network?.let { cm.getNetworkCapabilities(it) }
        val resolvers = fromLink(network?.let { cm.getLinkProperties(it) }, allowIpv6)
            .split(',')
            .map(String::trim)
            .filter(String::isNotEmpty)
            .distinct()
        val transport = when {
            capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "Wi-Fi"
            capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "Datos móviles"
            capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "Ethernet"
            network == null -> "Sin red física"
            else -> "Otra red"
        }
        ActiveDnsSnapshot(
            network = network,
            resolvers = resolvers,
            transport = transport,
            validated = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true,
        )
    } catch (_: Throwable) {
        ActiveDnsSnapshot(null, emptyList(), "Sin red física", false)
    }

    fun activeServers(context: Context, allowIpv6: Boolean = true): List<String> =
        activeSnapshot(context, allowIpv6).resolvers

    fun active(context: Context, allowIpv6: Boolean = true): String =
        activeServers(context, allowIpv6).joinToString(",")

    fun firstActiveDns(context: Context): String =
        activeServers(context, allowIpv6 = false).firstOrNull() ?: EMERGENCY_DNS

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
