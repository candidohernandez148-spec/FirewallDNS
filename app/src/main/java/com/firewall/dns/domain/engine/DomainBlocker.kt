package com.firewall.dns.domain.engine

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.io.File
import java.io.InputStream

object DomainBlocker {

    private val DEFAULT_DOMAINS = listOf(
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "google-analytics.com",
        "adservice.google.com",
        "adsrvr.org",
        "adnxs.com",
        "taboola.com",
        "outbrain.com",
        "criteo.com",
        "scorecardresearch.com",
        "quantserve.com",
        "moatads.com",
        "amazon-adsystem.com",
        "ads.facebook.com",
        "pixel.facebook.com",
        "analytics.facebook.com",
        "app-measurement.com",
        "appsflyer.com",
        "adjust.com",
        "branch.io",
        "mixpanel.com",
        "hotjar.com",
        "flurry.com",
        "unityads.unity3d.com",
        "applovin.com",
        "ironsrc.com",
        "mopub.com",
        "inmobi.com",
        "vungle.com"
    )

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var blocked: HashSet<String> = HashSet(DEFAULT_DOMAINS)

    val size: Int get() = blocked.size

    fun isBlocked(domain: String): Boolean {
        val d = normalize(domain)
        if (d.isEmpty()) return false
        val set = blocked
        var candidate = d
        while (true) {
            if (set.contains(candidate)) return true
            val dot = candidate.indexOf('.')
            if (dot < 0) return false
            candidate = candidate.substring(dot + 1)
        }
    }

    fun normalize(domain: String): String =
        domain.trim().lowercase().trimEnd('.')

    fun loadFromFile(file: File): Job = scope.launch {
        if (file.exists()) file.inputStream().use { merge(parse(it)) }
    }

    fun loadFromAsset(context: Context, assetName: String): Job {
        val appContext = context.applicationContext
        return scope.launch {
            appContext.assets.open(assetName).use { merge(parse(it)) }
        }
    }

    fun loadFromLines(lines: Collection<String>): Job = scope.launch {
        merge(lines.mapNotNullTo(HashSet()) { parseLine(it) })
    }

    @Synchronized
    fun reset() {
        blocked = HashSet(DEFAULT_DOMAINS)
    }

    @Synchronized
    private fun merge(extra: Set<String>) {
        val next = HashSet<String>(blocked.size + extra.size)
        next.addAll(blocked)
        next.addAll(extra)
        blocked = next
    }

    private fun parse(input: InputStream): Set<String> {
        val result = HashSet<String>()
        input.bufferedReader().useLines { lines ->
            lines.forEach { line -> parseLine(line)?.let(result::add) }
        }
        return result
    }

    private fun parseLine(raw: String): String? {
        val line = raw.substringBefore('#').trim()
        if (line.isEmpty()) return null
        val parts = line.split(Regex("\\s+"))
        val candidate = if (parts.size >= 2) parts[1] else parts[0]
        val domain = normalize(candidate.removePrefix("*."))
        if (domain.isEmpty() || domain == "localhost" || !domain.contains('.')) return null
        return domain
    }
}
