package com.firewall.dns.domain.engine

/** Evaluador determinista: usa reglas activas, catálogo curado y señales del dominio en tiempo real. */
object SmartDecisionEngine {
    enum class Level { ALLOW, OBSERVE, BLOCK }
    data class Decision(val level: Level, val score: Int, val reason: String)

    @Volatile
    private var blocklistKnowledge: Set<String> = emptySet()

    fun updateBlocklistKnowledge(domains: Set<String>) {
        blocklistKnowledge = domains
    }

    private val safeHosts = setOf(
        "www.facebook.com", "m.facebook.com", "web.facebook.com", "graph.facebook.com",
        "edge-mqtt.facebook.com", "www.instagram.com", "i.instagram.com", "graph.instagram.com",
        "www.tiktok.com", "m.tiktok.com", "www.whatsapp.com", "web.whatsapp.com",
        "whatsapp.net", "telegram.org", "t.me", "googlevideo.com", "youtube.com",
        "googleapis.com", "gstatic.com", "android.com", "samsung.com",
        "samsungcloud.com", "paypal.com", "stripe.com", "mercadolibre.com"
    )
    private val strongTokens = setOf(
        "adserver", "adservice", "adsystem", "adtech", "adnxs",
        "doubleclick", "googlesyndication", "googleadservices", "app-measurement",
        "adsrvr", "amazon-adsystem", "scorecardresearch", "quantserve", "moatads",
        "demdex", "everesttech", "bluekai", "krxd", "adform", "smartadserver",
        "adcolony", "smaato", "bidswitch", "casalemedia", "contextweb",
        "indexexchange", "33across", "sharethrough", "triplelift", "gumgum",
        "yieldmo", "pubnative", "mediavine", "undertone", "lijit", "openx",
        "pubmatic", "rubiconproject", "criteo", "taboola", "outbrain",
        "unityads", "applovin", "ironsource", "vungle", "chartboost"
    )
    private val mediumTokens = setOf(
        "ad", "ads", "pixel", "beacon", "telemetry", "analytics", "tracking", "tracker",
        "metrics", "click", "impression", "collect", "events", "log", "logs",
        "monitor", "stat", "stats", "ping", "report", "measurement"
    )
    private val metaRoots = setOf("facebook.com", "instagram.com", "fb.com")
    private val tiktokRoots = setOf("tiktok.com", "tiktokv.com", "byteoversea.com", "tiktokw.us")
    private val metaAd = setOf("ads", "ad", "pixel", "an", "tr")
    private val metaMeasure = setOf("analytics", "logging", "scribe", "tracking", "events")
    private val tiktokAd = setOf("ads", "ad", "pangle", "adservice", "adserver")
    private val tiktokMeasure = setOf("analytics", "log", "mon", "telemetry", "metrics", "mcs", "pitaya", "tracking")

    fun evaluate(domain: String): Decision? {
        val clean = domain.trim().lowercase().trimEnd('.')
        if (clean.isEmpty() || clean.length > 253) return null
        val labels = clean.split('.')
        if (labels.size < 2 || labels.any { it.isEmpty() || it.length > 63 }) return null
        if (clean in safeHosts) return null

        if (matchesDomainOrParent(clean, blocklistKnowledge)) {
            return Decision(
                Level.BLOCK, 5,
                "Bloqueado: dominio conocido por las listas de protección | Evidencia: coincidencia con una regla activa o un subdominio suyo | Confianza: muy alta | Criterio: las listas verificadas tienen prioridad sobre las heurísticas"
            )
        }

        ThreatKnowledgeGraph.inspect(clean)?.let { evidence ->
            val category = when (evidence.category) {
                ThreatKnowledgeGraph.Category.ADVERTISING -> "publicidad"
                ThreatKnowledgeGraph.Category.TRACKING -> "rastreo"
                ThreatKnowledgeGraph.Category.ANALYTICS -> "analítica"
            }
            val highConfidence = evidence.confidence == ThreatKnowledgeGraph.Confidence.HIGH
            val level = if (highConfidence) Level.BLOCK else Level.OBSERVE
            val label = if (level == Level.BLOCK) "Bloqueado" else "Observado; se permite"
            val confidence = if (highConfidence) "alta" else "media"
            return Decision(
                level,
                if (highConfidence) 5 else 2,
                "$label: relación del catálogo de amenazas con ${evidence.provider} " +
                    "(${evidence.relation}; $category) | Evidencia: ${evidence.knowledgePath.joinToString(" → ")} | " +
                    "Confianza: $confidence | Criterio: ${if (highConfidence) "proveedor publicitario de confianza alta" else "la evidencia no alcanza el umbral de bloqueo automático"}"
            )
        }

        val tokens = labels.flatMap { it.split('-', '_') }.toSet()
        val parts = labels.dropLast(1)
        var score = 0
        var strong = false
        val reasons = linkedSetOf<String>()

        if (tokens.any { it in strongTokens }) {
            score += 5
            strong = true
            reasons += "Proveedor publicitario o rastreador conocido"
        }
        val isMeta = metaRoots.any { clean.endsWith(".$it") }
        val isTikTok = tiktokRoots.any { clean.endsWith(".$it") }
        if (isMeta && parts.any { it in metaAd }) {
            score += 5; strong = true; reasons += "Publicidad Meta"
        } else if (isMeta && parts.any { it in metaMeasure }) {
            score += 5; strong = true; reasons += "Medición Meta"
        }
        if (isTikTok && parts.any { it in tiktokAd }) {
            score += 5; strong = true; reasons += "Publicidad TikTok"
        } else if (isTikTok && parts.any { it in tiktokMeasure }) {
            score += 5; strong = true; reasons += "Medición TikTok"
        }

        val matchedMediumSignals = tokens.filter { it in mediumTokens }.sorted()
        var reinforcedCompound = false
        if (!strong && matchedMediumSignals.isNotEmpty()) {
            when {
                matchedMediumSignals.size >= 3 -> {
                    score += 5
                    reinforcedCompound = true
                    reasons += "Patrón publicitario/rastreo reforzado: ${matchedMediumSignals.joinToString(", ")}"
                }
                matchedMediumSignals.size >= 2 -> {
                    score += 3
                    reasons += "Patrón compuesto de señales débiles: ${matchedMediumSignals.joinToString(", ")}"
                }
                else -> {
                    score += 2
                    reasons += "Indicador de medición o telemetría: ${matchedMediumSignals.first()}"
                }
            }
        }
        val first = labels.first()
        if (first.length >= 18 && first.count { it.isDigit() } >= 5) {
            score += 1
            reasons += "Subdominio de apariencia automatizada"
        }
        if (score == 0) return null

        val level = when {
            (strong || reinforcedCompound) && score >= 5 -> Level.BLOCK
            score >= 2 -> Level.OBSERVE
            else -> Level.ALLOW
        }
        val label = if (level == Level.BLOCK) "Bloqueado" else "Observado; se permite"
        val confidence = when {
            strong && score >= 5 -> "alta"
            reinforcedCompound && score >= 5 -> "media-alta"
            score >= 2 -> "media"
            else -> "baja"
        }
        val criterion = when {
            strong && score >= 5 -> "señal fuerte con puntuación suficiente"
            reinforcedCompound && score >= 5 -> "tres o más indicadores débiles independientes en el mismo dominio"
            score >= 2 -> "señales débiles: se observa sin bloquear"
            else -> "puntuación insuficiente para bloquear"
        }
        return Decision(
            level,
            score,
            "$label: ${reasons.joinToString(" + ")} | Señales: ${reasons.size} | " +
                "Puntuación: $score | Confianza: $confidence | Criterio: $criterion"
        )
    }

    private fun matchesDomainOrParent(domain: String, domains: Set<String>): Boolean {
        var candidate = domain
        while (true) {
            if (domains.contains(candidate)) return true
            val dot = candidate.indexOf('.')
            if (dot < 0) return false
            candidate = candidate.substring(dot + 1)
        }
    }
}
