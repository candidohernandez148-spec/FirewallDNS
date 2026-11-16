package com.firewall.dns.domain.model

import androidx.compose.ui.graphics.ImageBitmap

// Una muestra de actividad por intervalo para la gráfica en tiempo real.
data class TrafficPoint(val allowed: Int, val blocked: Int)

data class DnsLogEntry(
    val id: Long,
    val timestamp: String,
    val domain: String,
    val queryType: String,
    val isBlocked: Boolean,
    val reason: String,
    val appName: String
)

// Servidores recuperados del historial (Quad9, Google, AdGuard y Cloudflare) con su equivalente DoH.
enum class DnsProvider(val id: String, val label: String, val description: String, val ip: String, val bootstrapIps: String, val dohUrl: String) {
    CLOUDFLARE("cloudflare", "Cloudflare", "Rápido y privado", "1.1.1.1", "1.1.1.1,1.0.0.1,2606:4700:4700::1111", "https://cloudflare-dns.com/dns-query"),
    QUAD9("quad9", "Quad9", "Seguridad y privacidad", "9.9.9.9", "9.9.9.9,149.112.112.112,2620:fe::fe", "https://dns.quad9.net/dns-query"),
    GOOGLE("google", "Google DNS", "Resolución de Google", "8.8.8.8", "8.8.8.8,8.8.4.4,2001:4860:4860::8888", "https://dns.google/dns-query"),
    ADGUARD("adguard", "AdGuard DNS", "Bloqueo DNS adicional", "94.140.14.14", "94.140.14.14,94.140.15.15,2a10:50c0::ad1:ff", "https://dns.adguard-dns.com/dns-query");

    val transportId: String get() = "doh-$id"

    companion object {
        fun fromId(id: String?): DnsProvider = entries.firstOrNull { it.id == id } ?: CLOUDFLARE
    }
}

data class FirewallStats(
    val isRunning: Boolean = false,
    val engine: String = "",
    val totalAllowed: Long = 0,
    val totalBlocked: Long = 0,
    val loadedRulesCount: Int = 0,
    val networkType: String = "Sin red",
    val learnedTokens: Int = 0,
    val dnsProvider: DnsProvider = DnsProvider.CLOUDFLARE
)

data class DnsQueryInfo(
    val domain: String,
    val qType: Int,
    val questionEndOffset: Int
)

data class AppInfoItem(
    val label: String,
    val packageName: String,
    val icon: ImageBitmap? = null,
    val uid: Int = -1
)
