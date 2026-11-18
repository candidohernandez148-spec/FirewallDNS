package com.firewall.dns.domain.security

import com.firewall.dns.domain.model.DnsLogEntry

enum class DnsRiskLevel { LOW, MEDIUM, HIGH }

data class DnsRiskAssessment(
    val level: DnsRiskLevel,
    val score: Int,
    val analyzedEvents: Int,
    val findings: List<String>
)

/**
 * Conservative heuristics over locally recorded DNS events only.
 * This is an activity signal, not malware detection or a device scan.
 */
object DnsActivityAnalyzer {
    private const val SAMPLE_SIZE = 50
    private const val APP_DOMAIN_BURST_THRESHOLD = 25
    private const val REPEATED_BLOCK_THRESHOLD = 5
    private const val GENERATED_HOST_THRESHOLD = 3

    fun assess(logs: List<DnsLogEntry>): DnsRiskAssessment {
        val sample = logs.take(SAMPLE_SIZE)
        val findings = mutableListOf<String>()
        var score = 0

        val appBurst = sample
            .filter { it.appName.isNotBlank() && it.domain.isNotBlank() }
            .groupBy { it.appName.trim().lowercase() }
            .mapValues { (_, events) -> events.map { normalizeDomain(it.domain) }.filter { it.isNotBlank() }.distinct().size }
            .maxByOrNull { it.value }

        if (appBurst != null && appBurst.value >= APP_DOMAIN_BURST_THRESHOLD) {
            score += 2
            findings += "${appBurst.key}: consultó ${appBurst.value} dominios distintos en los últimos ${sample.size} eventos."
        }

        val repeatedBlocked = sample
            .filter { it.isBlocked && it.domain.isNotBlank() }
            .groupingBy { normalizeDomain(it.domain) }
            .eachCount()
            .filterValues { it >= REPEATED_BLOCK_THRESHOLD }
            .maxByOrNull { it.value }

        if (repeatedBlocked != null) {
            score += 1
            findings += "El dominio ${repeatedBlocked.key} aparece bloqueado ${repeatedBlocked.value} veces en la muestra."
        }

        val generatedHosts = sample.mapNotNull { entry ->
            val host = normalizeDomain(entry.domain)
            val firstLabel = host.substringBefore('.')
            val digitRatio = if (firstLabel.isEmpty()) 0.0 else firstLabel.count(Char::isDigit).toDouble() / firstLabel.length
            host.takeIf { firstLabel.length >= 24 && digitRatio >= 0.35 }
        }.distinct()

        if (generatedHosts.size >= GENERATED_HOST_THRESHOLD) {
            score += 1
            findings += "Se observaron ${generatedHosts.size} nombres de host largos con alta proporción de dígitos."
        }

        val level = when {
            score >= 3 -> DnsRiskLevel.HIGH
            score >= 2 -> DnsRiskLevel.MEDIUM
            else -> DnsRiskLevel.LOW
        }
        return DnsRiskAssessment(level, score, sample.size, findings)
    }

    private fun normalizeDomain(domain: String): String =
        domain.trim().trimEnd('.').lowercase()
}
