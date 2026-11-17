package com.firewall.dns.domain.engine

object SmartDomainAnalyzer {

    private val CORE_SAFE_HOSTS = setOf(
        "www.facebook.com", "m.facebook.com", "web.facebook.com", "graph.facebook.com",
        "edge-mqtt.facebook.com", "star.c10r.facebook.com", "fbcdn.net", "fbsbx.com",
        "www.instagram.com", "i.instagram.com", "graph.instagram.com", "cdninstagram.com",
        "www.tiktok.com", "m.tiktok.com", "tiktokcdn.com", "tiktokcdn-us.com",
        "tiktokcdn-eu.com", "byteoversea.com", "ibyteimg.com", "ibytedtos.com",
        "whatsapp.net", "whatsapp.com", "telegram.org", "t.me",
        "googlevideo.com", "ytimg.com", "googleapis.com", "gstatic.com",
        "googleusercontent.com", "google.com", "android.com", "samsung.com",
        "samsungcloud.com", "paypal.com", "stripe.com", "mercadopago.com", "mercadolibre.com"
    )

    private val GENERIC_TOKENS = setOf(
        "www", "api", "cdn", "m", "app", "static", "img", "image", "video",
        "media", "mobile", "edge", "gateway", "auth", "login", "account",
        "accounts", "mail", "play", "web", "v1", "v2", "v3", "s1", "s2", "com", "net", "org",
        "update", "updates", "download", "dl", "store", "shop", "cloud", "push", "sync",
        "config", "data", "service", "services", "time", "ntp", "dns", "cache", "content",
        "secure", "assets", "files", "downloads", "live", "chat", "search", "maps", "photos",
        "client", "clients", "portal", "status", "docs", "help", "support", "geo",
        "stream", "player", "feed", "region", "info", "news", "blog"
    )

    private val SECOND_LEVEL_TLDS = setOf("com", "net", "org", "gob", "edu", "co", "ac")

    private val HIGH_CONFIDENCE_TOKENS = setOf(
        "ads", "adserver", "adservice", "adsystem", "adtech", "adnxs",
        "doubleclick", "googlesyndication", "googleadservices", "app-measurement",
        "pixel", "beacon", "telemetry", "analytics", "tracking", "tracker",
        "crashlytics", "appsflyer", "adjust", "amplitude", "mixpanel",
        "unityads", "applovin", "ironsource", "vungle", "mopub", "chartboost",
        "taboola", "outbrain", "criteo", "pubmatic", "openx", "rubiconproject"
    )

    private val MEDIUM_TOKENS = setOf(
        "ad", "metrics", "click", "clicks", "impression", "impressions",
        "collect", "events", "log", "logs", "mon", "stat", "stats", "ping", "report"
    )

    private val META_TRACKER_TOKENS = setOf(
        "pixel", "an", "tr", "ads", "analytics", "logging", "scribe", "graph-fallback"
    )

    private val TIKTOK_TRACKER_TOKENS = setOf(
        "ads", "analytics", "log", "mon", "telemetry", "metrics", "mcs",
        "pitaya", "ad", "pangolin", "pangle"
    )

    fun evaluate(domain: String, learnedWeights: Map<String, Int>): Pair<Boolean, String>? {
        val clean = domain.lowercase()

        if (matchesDomainOrParent(clean, CORE_SAFE_HOSTS)) {
            return null
        }

        val labels = clean.split('.')
        if (labels.size < 2) return null

        val parts = labels.dropLast(1).flatMap { it.split('-', '_') }
        val tokens = learnableTokens(clean)

        if (tokens.any { (learnedWeights[it] ?: 0) <= -2 }) return null
        val strongest = tokens.maxByOrNull { learnedWeights[it] ?: 0 }
        val learnedMax = strongest?.let { learnedWeights[it] } ?: 0
        if (learnedMax >= 3) return true to "IA aprendido ($strongest)"

        var score = 0
        var category = "Heurística"

        if (clean.endsWith(".facebook.com") || clean.endsWith(".instagram.com") || clean.endsWith(".fb.com")) {
            if (parts.any { it in META_TRACKER_TOKENS }) {
                score += 3
                category = "Meta Tracker"
            }
        }

        if (clean.endsWith(".tiktok.com") || clean.endsWith(".tiktokv.com") ||
            clean.endsWith(".byteoversea.com") || clean.endsWith(".tiktokw.us")
        ) {
            if (parts.any { it in TIKTOK_TRACKER_TOKENS }) {
                score += 3
                category = "TikTok Tracker"
            }
        }

        if (parts.any { it in HIGH_CONFIDENCE_TOKENS }) {
            score += 3
            if (category == "Heurística") category = "Ads/Tracker"
        } else if (parts.any { it in MEDIUM_TOKENS }) {
            score += 2
            if (category == "Heurística") category = "Telemetría"
        }

        if (labels.size >= 4 && score > 0) {
            score += 1
        }
        val leftmost = labels.first()
        if (leftmost.length >= 10 && leftmost.count { it.isDigit() } >= 4 &&
            !leftmost.startsWith("cdn") && !leftmost.startsWith("img") &&
            !leftmost.startsWith("static") && !leftmost.startsWith("video")
        ) {
            score += 1
        }

        if (learnedMax >= 1) score += 1

        return if (score >= 3) {
            true to "IA [${score}pts] $category"
        } else {
            null
        }
    }

    // Quita el dominio registrable (2 etiquetas en .com/.net, o 3 en .com.mx/.co.uk).
    fun learnableTokens(domain: String): List<String> {
        val labels = domain.lowercase().trimEnd('.').split('.')
        val rootLabels = if (labels.size >= 4 &&
            labels.last().length == 2 &&
            labels[labels.size - 2] in SECOND_LEVEL_TLDS
        ) 3 else 2

        if (labels.size <= rootLabels) return emptyList()
        return labels.dropLast(rootLabels)
            .flatMap { it.split('-', '_') }
            .map { it.trimEnd { c -> c.isDigit() } }
            .filter { it.length >= 2 && it !in GENERIC_TOKENS }
            .distinct()
    }

    fun isCoreSafe(domain: String): Boolean = matchesDomainOrParent(domain.lowercase(), CORE_SAFE_HOSTS)

    fun updateLearning(
        domain: String,
        blocked: Boolean,
        weights: MutableMap<String, Int>,
        step: Int = 1
    ): Boolean {
        if (blocked && isCoreSafe(domain)) return false
        var changed = false
        for (token in learnableTokens(domain)) {
            val current = weights[token] ?: 0
            val next = if (blocked) (current + step).coerceAtMost(5) else (current - 3).coerceAtLeast(-5)
            if (next != current) {
                if (next == 0) weights.remove(token) else weights[token] = next
                changed = true
            }
        }
        return changed
    }

    private fun matchesDomainOrParent(domain: String, set: Set<String>): Boolean {
        var current = domain
        while (true) {
            if (set.contains(current)) return true
            val dot = current.indexOf('.')
            if (dot == -1) break
            current = current.substring(dot + 1)
        }
        return false
    }
}
