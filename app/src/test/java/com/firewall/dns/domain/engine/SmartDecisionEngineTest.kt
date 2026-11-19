package com.firewall.dns.domain.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SmartDecisionEngineTest {
    @Test fun knownAdTechIsBlockedWithStrongEvidence() {
        assertEquals(SmartDecisionEngine.Level.BLOCK, SmartDecisionEngine.evaluate("sync.adsrvr.org")?.level)
        assertEquals(SmartDecisionEngine.Level.BLOCK, SmartDecisionEngine.evaluate("pagead2.googlesyndication.com")?.level)
    }

    @Test fun metaAndTikTokSignalsDoNotBlockPlatformRoots() {
        assertEquals(SmartDecisionEngine.Level.BLOCK, SmartDecisionEngine.evaluate("ads.facebook.com")?.level)
        assertEquals(SmartDecisionEngine.Level.BLOCK, SmartDecisionEngine.evaluate("pixel.instagram.com")?.level)
        assertEquals(SmartDecisionEngine.Level.BLOCK, SmartDecisionEngine.evaluate("analytics.tiktok.com")?.level)
        assertNull(SmartDecisionEngine.evaluate("www.facebook.com"))
        assertNull(SmartDecisionEngine.evaluate("www.instagram.com"))
        assertNull(SmartDecisionEngine.evaluate("www.tiktok.com"))
    }

    @Test fun weakSignalsAreObservedAndAllowed() {
        val result = SmartDecisionEngine.evaluate("analytics.example.org")
        assertEquals(SmartDecisionEngine.Level.OBSERVE, result?.level)
        assertTrue(result?.reason?.contains("se permite") == true)
    }

    @Test fun multipleDistinctWeakSignalsFormAnObservableCompoundPattern() {
        val result = SmartDecisionEngine.evaluate("analytics-telemetry.example.org")
        assertEquals(SmartDecisionEngine.Level.OBSERVE, result?.level)
        assertTrue(result?.reason?.contains("Patrón compuesto de señales débiles") == true)
        assertTrue(result?.reason?.contains("analytics") == true)
        assertTrue(result?.reason?.contains("telemetry") == true)
        assertTrue(result?.reason?.contains("Confianza: media") == true)
    }

    @Test fun aSingleWeakSignalRemainsAnOrdinaryObservation() {
        val result = SmartDecisionEngine.evaluate("analytics.example.org")
        assertEquals(SmartDecisionEngine.Level.OBSERVE, result?.level)
        assertTrue(result?.reason?.contains("Indicador de medición o telemetría: analytics") == true)
        assertTrue(result?.reason?.contains("Patrón compuesto") != true)
    }

    @Test fun threeIndependentWeakSignalsTriggerAnExplainableBlock() {
        val result = SmartDecisionEngine.evaluate("ads-pixel-analytics.example.org")
        assertEquals(SmartDecisionEngine.Level.BLOCK, result?.level)
        assertTrue(result?.reason?.contains("Patrón publicitario/rastreo reforzado") == true)
        assertTrue(result?.reason?.contains("Confianza: media-alta") == true)
        assertTrue(result?.reason?.contains("tres o más indicadores débiles independientes") == true)
    }

    @Test fun ordinaryDomainsRemainAllowed() {
        assertNull(SmartDecisionEngine.evaluate("api.example.org"))
        assertNull(SmartDecisionEngine.evaluate("mail.google.com"))
    }

    @Test fun heuristicDecisionsExposeSignalsScoreConfidenceAndCriterion() {
        val result = SmartDecisionEngine.evaluate("analytics.example.org")
        assertEquals(SmartDecisionEngine.Level.OBSERVE, result?.level)
        assertTrue(result?.reason?.contains("Señales:") == true)
        assertTrue(result?.reason?.contains("Puntuación:") == true)
        assertTrue(result?.reason?.contains("Confianza: media") == true)
        assertTrue(result?.reason?.contains("señales débiles") == true)
    }

    @Test fun blocklistDecisionExplainsItsPriorityAndEvidence() {
        SmartDecisionEngine.updateBlocklistKnowledge(setOf("known-tracker.example"))
        try {
            val result = SmartDecisionEngine.evaluate("cdn.known-tracker.example")
            assertEquals(SmartDecisionEngine.Level.BLOCK, result?.level)
            assertTrue(result?.reason?.contains("Evidencia:") == true)
            assertTrue(result?.reason?.contains("Confianza: muy alta") == true)
            assertTrue(result?.reason?.contains("prioridad") == true)
        } finally {
            SmartDecisionEngine.updateBlocklistKnowledge(emptySet())
        }
    }

    @Test fun downloadedBlocklistBecomesHighConfidenceEngineKnowledge() {
        SmartDecisionEngine.updateBlocklistKnowledge(setOf("known-tracker.example"))
        try {
            assertEquals(
                SmartDecisionEngine.Level.BLOCK,
                SmartDecisionEngine.evaluate("cdn.known-tracker.example")?.level
            )
        } finally {
            SmartDecisionEngine.updateBlocklistKnowledge(emptySet())
        }
    }
}
