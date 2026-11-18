package com.firewall.dns.domain.engine

/** Motor local de evidencias: las señales débiles se observan; las fuertes pueden bloquear. */
object SmartDecisionEngine {
    enum class Level { ALLOW, OBSERVE, BLOCK }
    data class Decision(val level: Level, val score: Int, val reason: String)

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
        if (!strong && tokens.any { it in mediumTokens }) {
            score += 2
            reasons += "Indicador de medición o telemetría"
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

        val hasLearnedAllow = tokens.any { (learnedWeights[it] ?: 0) <= -2 }
        val level = when {
            hasLearnedAllow -> Level.OBSERVE
            strong && score >= 5 -> Level.BLOCK
            score >= 2 -> Level.OBSERVE
            else -> Level.ALLOW
        }
        val label = if (level == Level.BLOCK) "Bloqueado" else "Observado; se permite"
        return Decision(level, score, "$label: ${reasons.joinToString(" + ")} (${score} pts)")
    }
}
