package com.firewall.dns.domain.ai

import org.json.JSONObject

data class LocalAiAnalysisResult(
    val summary: String,
    val recommendations: List<LocalAiDomainSuggestion>
)

data class LocalAiAnalysisApplication(
    val analysis: LocalAiAnalysisResult,
    val outcomes: List<LocalAiPolicyOutcome>
)

object LocalAiRecommendationParser {
    private const val MAX_RECOMMENDATIONS = 32
    private const val MAX_SUMMARY_CHARS = 500
    private const val MAX_REASON_CHARS = 240

    /**
     * Parses only the strict JSON contract requested by LocalAiEvidenceBuilder.
     * Invalid records are discarded; model text is never treated as executable policy.
     */
    fun parse(raw: String): LocalAiAnalysisResult? = runCatching {
        val start = raw.indexOf('{')
        val end = raw.lastIndexOf('}')
        if (start < 0 || end <= start) return null
        val root = JSONObject(raw.substring(start, end + 1))
        val summary = root.optString("summary").take(MAX_SUMMARY_CHARS)
        val entries = root.optJSONArray("recommendations")
            ?: return@runCatching null
        val recommendations = buildList {
            for (index in 0 until minOf(entries.length(), MAX_RECOMMENDATIONS)) {
                val item = entries.optJSONObject(index) ?: continue
                val domain = LocalAiPolicyGate.normalizeDomain(item.optString("domain")) ?: continue
                val category = runCatching {
                    LocalAiDomainCategory.valueOf(item.optString("category").uppercase())
                }.getOrNull() ?: continue
                val action = runCatching {
                    LocalAiSuggestedAction.valueOf(item.optString("action").uppercase())
                }.getOrNull() ?: continue
                val confidence = item.optDouble("confidence", Double.NaN).toFloat()
                if (!confidence.isFinite() || confidence !in 0f..1f) continue
                add(
                    LocalAiDomainSuggestion(
                        domain = domain,
                        category = category,
                        action = action,
                        confidence = confidence,
                        explanation = item.optString("reason").take(MAX_REASON_CHARS)
                    )
                )
            }
        }.distinctBy { it.domain }
        LocalAiAnalysisResult(summary, recommendations)
    }.getOrNull()
}
