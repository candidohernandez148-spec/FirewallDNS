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

    data class ObservationProfile(
        val domain: String,
        val allowedCount: Long,
        val blockedCount: Long
    )

    private data class ObservationSignal(
        val allowed: Boolean,
        val total: Long
    )

    @Volatile
    private var observations: Map<String, ObservationSignal> = emptyMap()

    /**
     * Publica un snapshot agregado desde SQLite. Se llama fuera del hilo DNS.
     * Solo conserva perfiles con evidencia suficiente; no almacena apps ni consultas crudas.
     */
    fun updateObservations(profiles: List<ObservationProfile>) {
        observations = profiles.asSequence()
            .filter { it.allowedCount >= 0L && it.blockedCount >= 0L }
            .filter { it.allowedCount + it.blockedCount >= MIN_OBSERVATIONS }
            .associate { profile ->
                profile.domain.trim().lowercase().trimEnd('.') to ObservationSignal(
                    allowed = profile.allowedCount.toDouble() /
                        (profile.allowedCount + profile.blockedCount).coerceAtLeast(1L) >= ALLOWED_RATIO,
                    total = profile.allowedCount + profile.blockedCount
                )
            }
            .filterKeys { it.isNotBlank() }
            .toMap()
    }

    /** Señal contextual exacta; evita propagar la reputación de un dominio a otros hosts. */
    fun isRepeatedlyAllowed(domain: String): Boolean =
        observations[domain.trim().lowercase().trimEnd('.')]?.let { it.allowed } == true

    fun hasRepeatedObservations(domain: String): Boolean =
        observations.containsKey(domain.trim().lowercase().trimEnd('.'))

    private const val MIN_OBSERVATIONS = 8L
    private const val ALLOWED_RATIO = 0.90

    /**
     * Catálogo semilla conservador:
     * - Los endpoints publicitarios específicos de plataformas sociales tienen confianza alta.
     * - facebook.net se mantiene como rastreo de confianza media porque también aloja SDKs
     *   y funciones de integración; por sí solo no provoca bloqueo automático.
     * - No se añaden raíces completas de Facebook, Instagram o TikTok como proveedores.
     */
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
        val domainRelation = if (clean == provider.domain) "dominio proveedor" else "subdominio de proveedor"
        val path = buildList {
            provider.platform?.let { add("plataforma: $it") }
            add("proveedor: ${provider.domain}")
            if (clean != provider.domain) add("dominio consultado: $clean")
        }
        return Evidence(
            provider = provider.domain,
            category = provider.category,
            confidence = provider.confidence,
            relation = domainRelation,
            platform = provider.platform,
            knowledgePath = path
        )
    }

    /** Snapshot de solo lectura para la interfaz; no se consulta desde el motor DNS. */
    fun catalogSnapshot(): List<Evidence> = providers.mapNotNull { inspect(it.domain) }

    /** Número de perfiles agregados con evidencia mínima; nunca expone datos crudos. */
    fun learnedProfileCount(): Int = observations.size

    /** Relaciones explícitas del catálogo; no se infieren por palabras del dominio. */
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
