package com.firewall.dns.domain.engine

/** Motor local de evidencias: las señales débiles se observan; las fuertes pueden bloquear. */
object SmartDecisionEngine {
    enum class Level { ALLOW, OBSERVE, BLOCK }
    data class Decision(val level: Level, val score: Int, val reason: String)

    // Referencia compartida a la colección concurrente del repositorio: no duplica miles
    // de dominios ni realiza lecturas de disco durante una consulta DNS.
    @Volatile
    private var blocklistKnowledge: Set<String> = emptySet()

    /** Sincroniza el conocimiento con las reglas activas cargadas desde las listas. */
    fun updateBlocklistKnowledge(domains: Set<String>) {
        blocklistKnowledge = domains
        ThreatKnowledgeGraph.updateBlocklistDomains(domains)
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

    fun evaluate(domain: String, learnedWeights: Map<String, Int> = emptyMap()): Decision? {
        val clean = domain.trim().lowercase().trimEnd('.')
        if (clean.isEmpty() || clean.length > 253) return null
        val labels = clean.split('.')
        if (labels.size < 2 || labels.any { it.isEmpty() || it.length > 63 }) return null
        if (clean in safeHosts) return null

        // Las listas verificadas son conocimiento de alta confianza. La coincidencia
        // incluye el dominio y sus subdominios, igual que el evaluador de reglas.
        if (matchesDomainOrParent(clean, blocklistKnowledge)) {
            return Decision(Level.BLOCK, 5, "Bloqueado: dominio conocido por las listas de protección | Evidencia: coincidencia con una regla activa o un subdominio suyo | Confianza: muy alta | Criterio: las listas verificadas tienen prioridad sobre las heurísticas")
        }

        val tokens = labels.flatMap { it.split('-', '_') }.toSet()
        val learnedAllow = tokens.any { (learnedWeights[it] ?: 0) <= -2 }
        // La memoria agregada solo influye con al menos 8 observaciones y 90% de permisos.
        // Se consulta un mapa en memoria; nunca se accede a SQLite desde el hilo DNS.
        val repeatedlyAllowed = ThreatKnowledgeGraph.isRepeatedlyAllowed(clean)

        // El grafo aporta contexto de proveedor: publicidad conocida puede bloquearse;
        // analítica y rastreo de confianza media se observan, sin bloqueo automático.
        ThreatKnowledgeGraph.inspect(clean)?.let { evidence ->
            val category = when (evidence.category) {
                ThreatKnowledgeGraph.Category.ADVERTISING -> "publicidad"
                ThreatKnowledgeGraph.Category.TRACKING -> "rastreo"
                ThreatKnowledgeGraph.Category.ANALYTICS -> "analítica"
            }
            val highConfidence = evidence.confidence == ThreatKnowledgeGraph.Confidence.HIGH
            val level = if (highConfidence && !learnedAllow && !repeatedlyAllowed) Level.BLOCK else Level.OBSERVE
            val score = if (highConfidence) 5 else 2
            val label = if (level == Level.BLOCK) "Bloqueado" else "Observado; se permite"
            val confidenceLabel = if (highConfidence) "alta" else "media"
            val learningNote = ThreatKnowledgeGraph.observationEvidence(clean)?.let {
                "; aprendizaje local: ${it.allowedCount} permisos y ${it.blockedCount} bloqueos " +
                    "de ${it.total} observaciones (${it.interpretation})"
            }.orEmpty()
            val criterion = when {
                level == Level.BLOCK -> "proveedor publicitario de confianza alta"
                repeatedlyAllowed -> "el permiso repetido evita el bloqueo heurístico"
                else -> "la evidencia no alcanza el umbral de bloqueo automático"
            }
            return Decision(
                level,
                score,
                "$label: relación del mapa de conocimiento con ${evidence.provider} " +
                    "(${evidence.relation}; $category$learningNote) | " +
                    "Evidencia: ${evidence.knowledgePath.joinToString(" → ")} | " +
                    "Confianza: $confidenceLabel | Criterio: $criterion"
            )
        }

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
        // Dos o más indicadores débiles distintos forman un patrón compuesto.
        // Esto eleva la prioridad de observación, nunca activa un bloqueo por sí solo.
        val matchedMediumSignals = tokens.filter { it in mediumTokens }.sorted()
        if (!strong && matchedMediumSignals.isNotEmpty()) {
            if (matchedMediumSignals.size >= 2) {
                score += 3
                reasons += "Patrón compuesto de señales débiles: ${matchedMediumSignals.joinToString(", ")}"
            } else {
                score += 2
                reasons += "Indicador de medición o telemetría: ${matchedMediumSignals.first()}"
            }
        }
        val first = labels.first()
        if (first.length >= 18 && first.count { it.isDigit() } >= 5) {
            score += 1
            reasons += "Subdominio de apariencia automatizada"
        }
        val learned = tokens.maxOfOrNull { learnedWeights[it] ?: 0 } ?: 0
        if (learned >= 2) {
            score += 1
            reasons += "Coincidencia con aprendizaje local"
        }
        if (score == 0) return null

        val hasLearnedAllow = learnedAllow || repeatedlyAllowed
        ThreatKnowledgeGraph.observationEvidence(clean)?.let { learning ->
            reasons += "Aprendizaje local: ${learning.allowedCount} permisos y " +
                "${learning.blockedCount} bloqueos de ${learning.total} observaciones " +
                "(${learning.interpretation})"
        }
        val level = when {
            hasLearnedAllow -> Level.OBSERVE
            strong && score >= 5 -> Level.BLOCK
            score >= 2 -> Level.OBSERVE
            else -> Level.ALLOW
        }
        val label = if (level == Level.BLOCK) "Bloqueado" else "Observado; se permite"
        val confidence = when {
            strong && score >= 5 && !hasLearnedAllow -> "alta"
            score >= 2 -> "media"
            else -> "baja"
        }
        val criterion = when {
            hasLearnedAllow -> "el aprendizaje local impide el bloqueo automático"
            strong && score >= 5 -> "señal fuerte con puntuación suficiente"
            score >= 2 -> "señales débiles: se observa sin bloquear"
            else -> "puntuación insuficiente para bloquear"
        }
        return Decision(
            level,
            score,
            "$label: ${reasons.joinToString(" + ")} | " +
                "Señales: ${reasons.size} | Puntuación: $score | " +
                "Confianza: $confidence | Criterio: $criterion"
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
