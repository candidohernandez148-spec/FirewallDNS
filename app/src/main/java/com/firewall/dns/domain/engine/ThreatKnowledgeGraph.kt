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

    data class ObservationEvidence(
        val allowedCount: Long,
        val blockedCount: Long
    ) {
        val total: Long get() = allowedCount + blockedCount
        val allowedRatio: Double get() = allowedCount.toDouble() / total.coerceAtLeast(1L)
        val blockedRatio: Double get() = blockedCount.toDouble() / total.coerceAtLeast(1L)
        val interpretation: String
            get() = when {
                allowedRatio >= ALLOWED_RATIO -> "posible falso positivo: predominan los permisos"
                blockedRatio >= ALLOWED_RATIO -> "predominan los bloqueos"
                else -> "historial mixto: requiere más evidencia"
            }
    }

    private data class ObservationSignal(
        val allowed: Boolean,
        val total: Long,
        val allowedCount: Long,
        val blockedCount: Long
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
                    total = profile.allowedCount + profile.blockedCount,
                    allowedCount = profile.allowedCount,
                    blockedCount = profile.blockedCount
                )
            }
            .filterKeys { it.isNotBlank() }
            .toMap()
    }

    /** Señal contextual exacta; evita propagar la reputación de un dominio a otros hosts. */
    fun isRepeatedlyAllowed(domain: String): Boolean =
        observations[domain.trim().lowercase().trimEnd('.')]?.let { it.allowed } == true

    /** Resumen explicable del aprendizaje local; solo perfiles con al menos ocho eventos. */
    fun observationEvidence(domain: String): ObservationEvidence? =
        observations[domain.trim().lowercase().trimEnd('.')]?.let {
            ObservationEvidence(it.allowedCount, it.blockedCount)
        }

    fun hasRepeatedObservations(domain: String): Boolean =
        observations.containsKey(domain.trim().lowercase().trimEnd('.'))

    enum class LearnedAssessmentStatus { REVIEW_CANDIDATE, POSSIBLE_FALSE_POSITIVE, MIXED_HISTORY }

    data class LearnedDomainAssessment(
        val domain: String,
        val allowedCount: Long,
        val blockedCount: Long,
        val status: LearnedAssessmentStatus,
        val explanation: String
    ) {
        val totalObservations: Long get() = allowedCount + blockedCount
    }

    /** Clasifica perfiles desconocidos con historial suficiente; nunca modifica decisiones DNS. */
    fun learnedDomainAssessments(): List<LearnedDomainAssessment> = observations.entries
        .asSequence()
        .filter { inspect(it.key) == null }
        .map { (domain, signal) ->
            val status = when {
                signal.blockedCount.toDouble() / signal.total.coerceAtLeast(1L) >= REVIEW_BLOCKED_RATIO -> LearnedAssessmentStatus.REVIEW_CANDIDATE
                signal.allowedCount.toDouble() / signal.total.coerceAtLeast(1L) >= ALLOWED_RATIO -> LearnedAssessmentStatus.POSSIBLE_FALSE_POSITIVE
                else -> LearnedAssessmentStatus.MIXED_HISTORY
            }
            val explanation = when (status) {
                LearnedAssessmentStatus.REVIEW_CANDIDATE -> "Candidato a revisión: predominan los bloqueos locales; todavía no es una amenaza confirmada."
                LearnedAssessmentStatus.POSSIBLE_FALSE_POSITIVE -> "Posible falso positivo: predominan los permisos locales; no se crea una excepción automática."
                LearnedAssessmentStatus.MIXED_HISTORY -> "Historial mixto: las observaciones no permiten una conclusión fiable."
            }
            LearnedDomainAssessment(domain, signal.allowedCount, signal.blockedCount, status, explanation)
        }
        .sortedWith(compareBy<LearnedDomainAssessment> { it.status.ordinal }.thenByDescending { it.totalObservations }.thenBy { it.domain })
        .toList()

    data class ProviderCorrelation(
        val provider: String,
        val platform: String?,
        val category: Category,
        val confidence: Confidence,
        val observedDomains: List<String>,
        val allowedCount: Long,
        val blockedCount: Long,
        val listedDomainCount: Int
    ) {
        val totalObservations: Long get() = allowedCount + blockedCount
    }

    @Volatile
    private var activeBlocklistDomains: Set<String> = emptySet()

    /** Publica un snapshot de reglas activas ya cargadas; no realiza I/O. */
    fun updateBlocklistDomains(domains: Set<String>) {
        activeBlocklistDomains = domains.asSequence()
            .map { it.trim().lowercase().trimEnd('.') }
            .filter { it.isNotBlank() }
            .toSet()
    }

    /**
     * Correlaciona únicamente dominios observados/listados que coinciden con un proveedor
     * explícito del catálogo. No atribuye proveedores por tokens, similitud o coincidencias parciales.
     */
    fun correlationSnapshot(): List<ProviderCorrelation> {
        val observed = observations.entries.mapNotNull { (domain, signal) ->
            inspect(domain)?.let { it.provider to (domain to signal) }
        }.groupBy({ it.first }, { it.second })

        val listed = activeBlocklistDomains.mapNotNull { domain ->
            inspect(domain)?.let { it.provider }
        }.groupingBy { it }.eachCount()

        return (observed.keys + listed.keys).distinct().mapNotNull { providerDomain ->
            val evidence = inspect(providerDomain) ?: return@mapNotNull null
            val entries = observed[providerDomain].orEmpty()
            ProviderCorrelation(
                provider = providerDomain,
                platform = evidence.platform,
                category = evidence.category,
                confidence = evidence.confidence,
                observedDomains = entries.map { it.first }.distinct().sorted(),
                allowedCount = entries.sumOf { it.second.allowedCount },
                blockedCount = entries.sumOf { it.second.blockedCount },
                listedDomainCount = listed[providerDomain] ?: 0
            )
        }.sortedWith(compareByDescending<ProviderCorrelation> { it.totalObservations + it.listedDomainCount }
            .thenBy { it.provider })
    }

    /** Perfiles con suficiente historial que no tienen una relación curada conocida. */
    fun unattributedLearnedProfileCount(): Int =
        observations.keys.count { inspect(it) == null }


    enum class PatternConfidence { LOW, MEDIUM, HIGH }

    /** Familia observada entre dominios desconocidos, respaldada por historial agregado. */
    data class AdaptivePattern(
        val indicators: List<String>,
        val domains: List<String>,
        val allowedCount: Long,
        val blockedCount: Long,
        val confidence: PatternConfidence
    ) {
        val totalObservations: Long get() = allowedCount + blockedCount
    }

    private val adaptiveIndicators = setOf(
        "ad", "ads", "advert", "analytics", "telemetry", "tracking", "tracker",
        "pixel", "beacon", "metrics", "measurement", "collect", "events",
        "monitor", "stats", "stat", "impression", "click"
    )

    /** Extrae señales exactas de etiquetas; no usa subcadenas ni similitud difusa. */
    private fun indicatorsForDomain(domain: String): List<String> = domain
        .split(Regex("[^a-z0-9]+"))
        .filter { it in adaptiveIndicators }
        .distinct()
        .sorted()

    /**
     * Agrupa familias repetidas entre dominios desconocidos. La confianza alta exige
     * al menos tres dominios, 24 eventos y 75% de bloqueos (mínimo 18 bloqueos).
     * Solo esa evidencia permite que una familia influya en decisiones DNS.
     */
    fun adaptivePatternSnapshot(): List<AdaptivePattern> {
        val groups = observations.entries.mapNotNull { (domain, signal) ->
            if (inspect(domain) != null) return@mapNotNull null
            val indicators = indicatorsForDomain(domain)
            if (indicators.isEmpty()) return@mapNotNull null
            indicators.joinToString("+") to (domain to signal)
        }.groupBy({ it.first }, { it.second })

        return groups.mapNotNull { (signature, entries) ->
            if (entries.size < MIN_PATTERN_DOMAINS) return@mapNotNull null
            val domains = entries.map { it.first }.distinct().sorted()
            val allowed = entries.sumOf { it.second.allowedCount }
            val blocked = entries.sumOf { it.second.blockedCount }
            val total = allowed + blocked
            val confidence = when {
                domains.size >= MIN_HIGH_CONFIDENCE_PATTERN_DOMAINS &&
                    total >= MIN_HIGH_CONFIDENCE_PATTERN_OBSERVATIONS &&
                    blocked >= MIN_HIGH_CONFIDENCE_BLOCKED_OBSERVATIONS &&
                    blocked.toDouble() / total.coerceAtLeast(1L) >= MIN_PATTERN_BLOCKED_RATIO -> PatternConfidence.HIGH
                domains.size >= 3 && total >= 24L -> PatternConfidence.MEDIUM
                else -> PatternConfidence.LOW
            }
            AdaptivePattern(
                indicators = signature.split("+"),
                domains = domains,
                allowedCount = allowed,
                blockedCount = blocked,
                confidence = confidence
            )
        }.sortedWith(
            compareByDescending<AdaptivePattern> { it.confidence.ordinal }
                .thenByDescending { it.totalObservations }
                .thenByDescending { it.domains.size }
                .thenBy { it.indicators.joinToString("+") }
        ).take(MAX_ADAPTIVE_PATTERNS)
    }

    /**
     * Devuelve una familia únicamente cuando el dominio comparte su firma exacta
     * con una familia de confianza alta. No atribuye un proveedor ni usa red/I-O.
     */
    fun blockedAdaptivePatternFor(domain: String): AdaptivePattern? {
        val clean = domain.trim().lowercase().trimEnd('.')
        if (clean.isBlank() || inspect(clean) != null) return null
        val indicators = indicatorsForDomain(clean)
        if (indicators.isEmpty()) return null
        val signature = indicators.joinToString("+")
        return adaptivePatternSnapshot().firstOrNull {
            it.confidence == PatternConfidence.HIGH && it.indicators.joinToString("+") == signature
        }
    }

    private const val MIN_PATTERN_DOMAINS = 2
    private const val MAX_ADAPTIVE_PATTERNS = 20

    private const val MIN_OBSERVATIONS = 8L
    private const val ALLOWED_RATIO = 0.90
    private const val REVIEW_BLOCKED_RATIO = 0.75

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
