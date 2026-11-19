package com.firewall.dns.domain.engine

/**
 * Catálogo determinista y local de proveedores conocidos de publicidad, tracking y analítica.
 * No recoge observaciones de tráfico, no aprende y no conserva perfiles de dominios.
 */
object ThreatKnowledgeGraph {
    enum class Category { ADVERTISING, TRACKING, ANALYTICS }
    enum class Confidence { HIGH, MEDIUM }

    data class Evidence(
        val provider: String,
        val category: Category,
        val confidence: Confidence,
        val relation: String,
        val platform: String? = null,
        val knowledgePath: List<String> = emptyList(),
        val source: String = "catálogo local curado"
    )

    enum class RelationType { OPERATES_PROVIDER, PROVIDES_ENDPOINT }

    data class KnowledgeRelation(
        val from: String,
        val to: String,
        val type: RelationType
    )

    private data class Provider(
        val domain: String,
        val category: Category,
        val confidence: Confidence,
        val platform: String? = null
    )

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
        Provider("ads.facebook.com", Category.ADVERTISING, Confidence.HIGH, "Meta"),
        Provider("pixel.facebook.com", Category.ADVERTISING, Confidence.HIGH, "Meta"),
        Provider("pixel.instagram.com", Category.ADVERTISING, Confidence.HIGH, "Meta"),
        Provider("pangle.io", Category.ADVERTISING, Confidence.HIGH, "ByteDance / Pangle"),
        Provider("pangleglobal.com", Category.ADVERTISING, Confidence.HIGH, "ByteDance / Pangle"),
        Provider("snapads.com", Category.ADVERTISING, Confidence.HIGH, "Snap"),
        Provider("ads-twitter.com", Category.ADVERTISING, Confidence.HIGH, "X"),
        Provider("facebook.net", Category.TRACKING, Confidence.MEDIUM),
        Provider("appsflyer.com", Category.TRACKING, Confidence.MEDIUM),
        Provider("adjust.com", Category.TRACKING, Confidence.MEDIUM),
        Provider("branch.io", Category.TRACKING, Confidence.MEDIUM),
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
        val relation = if (clean == provider.domain) "dominio proveedor" else "subdominio de proveedor"
        val path = buildList {
            provider.platform?.let { add("plataforma: $it") }
            add("proveedor: ${provider.domain}")
            if (clean != provider.domain) add("dominio consultado: $clean")
        }
        return Evidence(
            provider = provider.domain,
            category = provider.category,
            confidence = provider.confidence,
            relation = relation,
            platform = provider.platform,
            knowledgePath = path
        )
    }

    /** Catálogo de solo lectura para el mapa y panel de amenazas. */
    fun catalogSnapshot(): List<Evidence> = providers.mapNotNull { inspect(it.domain) }

    /** Relaciones explícitas del catálogo; no se infieren por palabras ni historial. */
    fun relationsFor(domain: String): List<KnowledgeRelation> {
        val evidence = inspect(domain) ?: return emptyList()
        val relations = mutableListOf<KnowledgeRelation>()
        evidence.platform?.let { platform ->
            relations += KnowledgeRelation(platform, evidence.provider, RelationType.OPERATES_PROVIDER)
        }
        relations += KnowledgeRelation(
            evidence.provider,
            domain.trim().lowercase().trimEnd('.'),
            RelationType.PROVIDES_ENDPOINT
        )
        return relations
    }
}
