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
}
