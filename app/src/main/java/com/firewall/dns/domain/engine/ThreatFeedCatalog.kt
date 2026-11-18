package com.firewall.dns.domain.engine

import java.net.URI

enum class ThreatFeedCategory(val displayName: String) {
    PHISHING("Phishing"),
    MALWARE_PHISHING("Malware y phishing"),
    ADS_TRACKING("Publicidad y rastreo"),
    GENERAL("Lista personalizada")
}

data class ThreatFeedPreset(
    val name: String,
    val description: String,
    val url: String,
    val category: ThreatFeedCategory
)

/**
 * Official DNS-compatible feeds. Category labels describe the publisher's stated purpose;
 * they are not a verdict on domains from unrelated/custom feeds.
 */
object ThreatFeedCatalog {
    val presets = listOf(
        ThreatFeedPreset(
            name = "Phishing Army",
            description = "Dominios de phishing",
            url = "https://phishing.army/download/phishing-army-adblock.txt",
            category = ThreatFeedCategory.PHISHING
        ),
        ThreatFeedPreset(
            name = "HaGeZi TIF Mini",
            description = "Malware, phishing, estafas y C2",
            url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt",
            category = ThreatFeedCategory.MALWARE_PHISHING
        ),
        ThreatFeedPreset(
            name = "AdGuard DNS",
            description = "Publicidad y rastreo a nivel DNS",
            url = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            category = ThreatFeedCategory.ADS_TRACKING
        )
    )

    fun categoryForUrl(rawUrl: String): ThreatFeedCategory {
        val uri = runCatching { URI(rawUrl.trim()) }.getOrNull() ?: return ThreatFeedCategory.GENERAL
        val host = uri.host?.lowercase() ?: return ThreatFeedCategory.GENERAL
        val path = uri.path.orEmpty()
        return presets.firstOrNull { preset ->
            val presetUri = URI(preset.url)
            presetUri.host.equals(host, ignoreCase = true) && presetUri.path == path
        }?.category ?: ThreatFeedCategory.GENERAL
    }

    fun matchesDomainOrParent(domain: String, domains: Set<String>): Boolean {
        var current = domain.trim().lowercase().trimEnd('.')
        while (current.isNotEmpty()) {
            if (current in domains) return true
            val dot = current.indexOf('.')
            if (dot < 0) return false
            current = current.substring(dot + 1)
        }
        return false
    }

    fun reasonFor(category: ThreatFeedCategory): String = when (category) {
        ThreatFeedCategory.PHISHING -> "Protección contra phishing (Phishing Army)"
        ThreatFeedCategory.MALWARE_PHISHING -> "Inteligencia de amenazas: malware, phishing y C2 (HaGeZi TIF Mini)"
        ThreatFeedCategory.ADS_TRACKING -> "Lista de publicidad y rastreo (AdGuard DNS)"
        ThreatFeedCategory.GENERAL -> "Lista DNS personalizada"
    }
}
