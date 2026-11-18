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

    @Test fun reinforcedCompoundSignalsDoNotOverrideLearnedAllowEvidence() {
        val result = SmartDecisionEngine.evaluate(
            "ads-pixel-analytics.example.org",
            mapOf("analytics" to -2)
        )
        assertEquals(SmartDecisionEngine.Level.OBSERVE, result?.level)
        assertTrue(result?.reason?.contains("el aprendizaje local impide el bloqueo automático") == true)
    }

    @Test fun compoundWeakSignalsNeverOverrideAnActiveAllowLearningSignal() {
        val result = SmartDecisionEngine.evaluate(
            "analytics-telemetry.example.org",
            mapOf("analytics" to -2)
        )
        assertEquals(SmartDecisionEngine.Level.OBSERVE, result?.level)
        assertTrue(result?.reason?.contains("el aprendizaje local impide el bloqueo automático") == true)
    }

    @Test fun highConfidenceBlockedFamilyBlocksANewRelatedDomain() {
        ThreatKnowledgeGraph.updateObservations(
            listOf(
                ThreatKnowledgeGraph.ObservationProfile("analytics-telemetry.alpha.example", 0, 8),
                ThreatKnowledgeGraph.ObservationProfile("analytics-telemetry.beta.example", 0, 8),
                ThreatKnowledgeGraph.ObservationProfile("analytics-telemetry.gamma.example", 0, 8)
            )
        )
        try {
            val result = SmartDecisionEngine.evaluate("analytics-telemetry.delta.example")
            assertEquals(SmartDecisionEngine.Level.BLOCK, result?.level)
            assertTrue(result?.reason?.contains("familia local de publicidad/rastreo") == true)
            assertTrue(result?.reason?.contains("24 bloqueos y 0 permisos") == true)
            assertTrue(result?.reason?.contains("Confianza: alta") == true)
        } finally {
            ThreatKnowledgeGraph.updateObservations(emptyList())
        }
    }

    @Test fun exactDomainPermissionOverridesLearnedBlockedFamily() {
        ThreatKnowledgeGraph.updateObservations(
            listOf(
                ThreatKnowledgeGraph.ObservationProfile("analytics-telemetry.alpha.example", 0, 8),
                ThreatKnowledgeGraph.ObservationProfile("analytics-telemetry.beta.example", 0, 8),
                ThreatKnowledgeGraph.ObservationProfile("analytics-telemetry.gamma.example", 0, 8),
                ThreatKnowledgeGraph.ObservationProfile("analytics-telemetry.delta.example", 8, 0)
            )
        )
        try {
            val result = SmartDecisionEngine.evaluate("analytics-telemetry.delta.example")
            assertEquals(SmartDecisionEngine.Level.OBSERVE, result?.level)
            assertTrue(result?.reason?.contains("permiso prevalece sobre la familia") == true)
        } finally {
            ThreatKnowledgeGraph.updateObservations(emptyList())
        }
    }

    @Test fun ordinaryDomainsRemainAllowed() {
        assertNull(SmartDecisionEngine.evaluate("api.example.org"))
        assertNull(SmartDecisionEngine.evaluate("mail.google.com"))
    }

    @Test fun learnedAllowSignalPreventsHeuristicBlock() {
        val result = SmartDecisionEngine.evaluate("ads.example.org", mapOf("ads" to -2))
        assertEquals(SmartDecisionEngine.Level.OBSERVE, result?.level)
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
            val result = SmartDecisionEngine.evaluate("cdn.known-tracker.example")
            assertEquals(SmartDecisionEngine.Level.BLOCK, result?.level)
            assertTrue(result?.reason?.contains("listas de protección") == true)
        } finally {
            SmartDecisionEngine.updateBlocklistKnowledge(emptySet())
        }
    }

}
