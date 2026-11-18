package com.firewall.dns.domain.engine

/**
 * Grafo determinista y local de conocimiento sobre proveedores.
 * Una coincidencia de subdominio hereda la relación de su dominio proveedor.
 * No atribuye tráfico a una aplicación ni consulta servicios externos.
 */
object ThreatKnowledgeGraph {
    enum class Category { ADVERTISING, TRACKING, ANALYTICS }
    enum class Confidence { HIGH, MEDIUM }

    data class Evidence(
        val provider: String,
        val category: Category,
        val confidence: Confidence,
        val relation: String
    )

    private data class Provider(
        val domain: String,
        val category: Category,
        val confidence: Confidence
    )

    // Nodos semilla: dominios de proveedor conocidos y su relación semántica.
    private val providers = listOf(
        Provider("doubleclick.net", Category.ADVERTISING, Confidence.HIGH),
        Provider("googlesyndication.com", Category.ADVERTISING, Confidence.HIGH),
        Provider("googleadservices.com", Category.ADVERTISING, Confidence.HIGH),
        Provider("amazon-adsystem.com", Category.ADVERTISING, Confidence.HIGH),
        Provider("adsrvr.org", Category.ADVERTISING, Confidence.HIGH),
        Provider("adnxs.com", Category.ADVERTISING, Confidence.HIGH),
        Provider("criteo.com", Category.ADVERTISING, Confidence.HIGH),
        Provider("taboola.com", Category.ADVERTISING, Confidence.HIGH),
        Provider("outbrain.com", Category.ADVERTISING, Confidence.HIGH),
        Provider("pubmatic.com", Category.ADVERTISING, Confidence.HIGH),
        Provider("openx.net", Category.ADVERTISING, Confidence.HIGH),
        Provider("unityads.unity3d.com", Category.ADVERTISING, Confidence.HIGH),
        Provider("appsflyer.com", Category.TRACKING, Confidence.MEDIUM),
        Provider("adjust.com", Category.TRACKING, Confidence.MEDIUM),
        Provider(" Branch.io", Category.TRACKING, Confidence.MEDIUM),
        Provider("mixpanel.com", Category.ANALYTICS, Confidence.MEDIUM),
        Provider("amplitude.com", Category.ANALYTICS, Confidence.MEDIUM),
        Provider("scorecardresearch.com", Category.TRACKING, Confidence.HIGH),
        Provider("quantserve.com", Category.TRACKING, Confidence.HIGH)
    )

    /** Devuelve la relación proveedor → dominio consultado, incluyendo subdominios. */
    fun inspect(domain: String): Evidence? {
        val clean = domain.trim().lowercase().trimEnd('.')
        if (clean.isEmpty()) return null
        val provider = providers.firstOrNull {
            clean == it.domain || clean.endsWith(".${it.domain}")
        } ?: return null
        return Evidence(
            provider = provider.domain,
            category = provider.category,
            confidence = provider.confidence,
            relation = if (clean == provider.domain) "dominio proveedor" else "subdominio de proveedor"
        )
    }
}
