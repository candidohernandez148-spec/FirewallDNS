package com.firewall.dns.domain.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatKnowledgeGraphTest {
    @Test fun knownAdvertisingProviderIsRelatedToItsSubdomains() {
        val evidence = ThreatKnowledgeGraph.inspect("cdn.doubleclick.net")
        assertEquals("doubleclick.net", evidence?.provider)
        assertEquals(ThreatKnowledgeGraph.Category.ADVERTISING, evidence?.category)
        assertEquals("subdominio de proveedor", evidence?.relation)
    }

    @Test fun unrelatedLookalikeDoesNotMatchProviderNode() {
        assertNull(ThreatKnowledgeGraph.inspect("notdoubleclick.net"))
    }

    @Test fun smartEngineBlocksHighConfidenceAdvertisingAndObservesAnalytics() {
        val advertising = SmartDecisionEngine.evaluate("cdn.doubleclick.net")
        assertEquals(SmartDecisionEngine.Level.BLOCK, advertising?.level)
        assertTrue(advertising?.reason?.contains("mapa de conocimiento") == true)

        val analytics = SmartDecisionEngine.evaluate("events.mixpanel.com")
        assertEquals(SmartDecisionEngine.Level.OBSERVE, analytics?.level)
        assertTrue(analytics?.reason?.contains("se permite") == true)
    }

    @Test fun learnedAllowDowngradesGraphBlockToObservation() {
        val result = SmartDecisionEngine.evaluate("cdn.doubleclick.net", mapOf("cdn" to -2))
        assertEquals(SmartDecisionEngine.Level.OBSERVE, result?.level)
    }
    @Test fun repeatedAllowedObservationsDowngradeExactProviderDomain() {
        ThreatKnowledgeGraph.updateObservations(
            listOf(
                ThreatKnowledgeGraph.ObservationProfile(
                    domain = "cdn.doubleclick.net",
                    allowedCount = 8,
                    blockedCount = 0
                )
            )
        )
        try {
            val result = SmartDecisionEngine.evaluate("cdn.doubleclick.net")
            assertEquals(SmartDecisionEngine.Level.OBSERVE, result?.level)
            assertTrue(result?.reason?.contains("permiso repetido aprendido") == true)
            // La evidencia no se propaga a otros dominios del mismo proveedor.
            assertEquals(
                SmartDecisionEngine.Level.BLOCK,
                SmartDecisionEngine.evaluate("other.doubleclick.net")?.level
            )
        } finally {
            ThreatKnowledgeGraph.updateObservations(emptyList())
        }
    }

    @Test fun contextualLearningRequiresEightObservationsAndNinetyPercentAllowed() {
        ThreatKnowledgeGraph.updateObservations(
            listOf(
                ThreatKnowledgeGraph.ObservationProfile(
                    domain = "cdn.doubleclick.net",
                    allowedCount = 7,
                    blockedCount = 0
                ),
                ThreatKnowledgeGraph.ObservationProfile(
                    domain = "pixel.doubleclick.net",
                    allowedCount = 8,
                    blockedCount = 1
                )
            )
        )
        try {
            assertEquals(
                SmartDecisionEngine.Level.BLOCK,
                SmartDecisionEngine.evaluate("cdn.doubleclick.net")?.level
            )
            assertEquals(
                SmartDecisionEngine.Level.BLOCK,
                SmartDecisionEngine.evaluate("pixel.doubleclick.net")?.level
            )
        } finally {
            ThreatKnowledgeGraph.updateObservations(emptyList())
        }
    }

    @Test fun repeatedAllowedSignalDoesNotOverrideActiveBlocklistKnowledge() {
        SmartDecisionEngine.updateBlocklistKnowledge(setOf("cdn.doubleclick.net"))
        ThreatKnowledgeGraph.updateObservations(
            listOf(
                ThreatKnowledgeGraph.ObservationProfile(
                    domain = "cdn.doubleclick.net",
                    allowedCount = 20,
                    blockedCount = 0
                )
            )
        )
        try {
            assertEquals(
                SmartDecisionEngine.Level.BLOCK,
                SmartDecisionEngine.evaluate("cdn.doubleclick.net")?.level
            )
        } finally {
            SmartDecisionEngine.updateBlocklistKnowledge(emptySet())
            ThreatKnowledgeGraph.updateObservations(emptyList())
        }
    }

}
