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

data class FirewallStats(
    val isRunning: Boolean = false,
    val engine: String = "",
    val totalAllowed: Long = 0,
    val totalBlocked: Long = 0,
    val loadedRulesCount: Int = 0,
    val networkType: String = "Sin red"
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
    val uid: Int = -1,
    val isSystemApp: Boolean = false
)


data class BlocklistDownloadProgress(
    val currentSource: Int,
    val totalSources: Int,
    val phase: String,
    val downloadedBytes: Long = 0L,
    val totalBytes: Long = -1L
) {
    val percent: Int?
        get() = if (totalBytes > 0L) {
            ((downloadedBytes.coerceAtMost(totalBytes) * 100L) / totalBytes).toInt()
        } else null
}
