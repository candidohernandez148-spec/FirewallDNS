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

    @Test fun socialPlatformAdEndpointsAreKnownWithoutClassifyingPlatformRoots() {
        val cases = mapOf(
            "ads.facebook.com" to "ads.facebook.com",
            "pixel.instagram.com" to "pixel.instagram.com",
            "cdn.pangle.io" to "pangle.io",
            "sdk.snapads.com" to "snapads.com",
            "pixel.ads-twitter.com" to "ads-twitter.com"
        )
        cases.forEach { (domain, provider) ->
            val evidence = ThreatKnowledgeGraph.inspect(domain)
            assertEquals(provider, evidence?.provider)
            assertEquals(ThreatKnowledgeGraph.Category.ADVERTISING, evidence?.category)
            assertEquals(ThreatKnowledgeGraph.Confidence.HIGH, evidence?.confidence)
        }

        assertNull(ThreatKnowledgeGraph.inspect("www.facebook.com"))
        assertNull(ThreatKnowledgeGraph.inspect("www.instagram.com"))
        assertNull(ThreatKnowledgeGraph.inspect("www.tiktok.com"))
    }

    @Test fun sharedSocialSdkDomainIsObservedRatherThanAutomaticallyBlocked() {
        val evidence = ThreatKnowledgeGraph.inspect("connect.facebook.net")
        assertEquals("facebook.net", evidence?.provider)
        assertEquals(ThreatKnowledgeGraph.Category.TRACKING, evidence?.category)
        assertEquals(ThreatKnowledgeGraph.Confidence.MEDIUM, evidence?.confidence)
        assertEquals(
            SmartDecisionEngine.Level.OBSERVE,
            SmartDecisionEngine.evaluate("connect.facebook.net")?.level
        )
    }

    @Test fun unrelatedLookalikeDoesNotMatchProviderNode() {
        assertNull(ThreatKnowledgeGraph.inspect("notdoubleclick.net"))
        assertNull(ThreatKnowledgeGraph.inspect("notpangle.io"))
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
            listOf(ThreatKnowledgeGraph.ObservationProfile("cdn.doubleclick.net", 8, 0))
        )
        try {
            val result = SmartDecisionEngine.evaluate("cdn.doubleclick.net")
            assertEquals(SmartDecisionEngine.Level.OBSERVE, result?.level)
            assertTrue(result?.reason?.contains("permiso repetido aprendido") == true)
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
                ThreatKnowledgeGraph.ObservationProfile("cdn.doubleclick.net", 7, 0),
                ThreatKnowledgeGraph.ObservationProfile("pixel.doubleclick.net", 8, 1)
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
            listOf(ThreatKnowledgeGraph.ObservationProfile("cdn.doubleclick.net", 20, 0))
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

    @Test fun socialProviderEvidenceExplainsItsPlatformAndKnowledgePath() {
        val evidence = ThreatKnowledgeGraph.inspect("pixel.instagram.com")
        assertEquals("Meta", evidence?.platform)
        assertEquals(
            listOf("plataforma: Meta", "proveedor: pixel.instagram.com"),
            evidence?.knowledgePath
        )
        assertEquals("catálogo local curado", evidence?.source)
    }

    @Test fun graphExposesOnlyExplicitPlatformProviderAndEndpointRelations() {
        val relations = ThreatKnowledgeGraph.relationsFor("cdn.pangle.io")
        assertEquals(2, relations.size)
        assertEquals("ByteDance / Pangle", relations[0].from)
        assertEquals("pangle.io", relations[0].to)
        assertEquals(ThreatKnowledgeGraph.RelationType.OPERATES_PROVIDER, relations[0].type)
        assertEquals("pangle.io", relations[1].from)
        assertEquals("cdn.pangle.io", relations[1].to)
        assertEquals(ThreatKnowledgeGraph.RelationType.PROVIDES_ENDPOINT, relations[1].type)
    }

    @Test fun unknownDomainsDoNotReceiveInventedPlatformRelations() {
        assertTrue(ThreatKnowledgeGraph.relationsFor("ads.unknown-social.example").isEmpty())
        assertNull(ThreatKnowledgeGraph.inspect("ads.unknown-social.example"))
    }

    @Test fun dashboardSnapshotExposesCuratedProvidersWithoutChangingDnsDecisions() {
        val snapshot = ThreatKnowledgeGraph.catalogSnapshot()
        assertTrue(snapshot.isNotEmpty())
        assertTrue(snapshot.any { it.provider == "doubleclick.net" })
        assertTrue(snapshot.any { it.provider == "pixel.instagram.com" && it.platform == "Meta" })
        assertTrue(snapshot.none { it.provider == "www.facebook.com" })
    }

    @Test fun learnedProfileCountReportsOnlyQualifiedAggregates() {
        ThreatKnowledgeGraph.updateObservations(
            listOf(
                ThreatKnowledgeGraph.ObservationProfile("qualified.example", 8, 0),
                ThreatKnowledgeGraph.ObservationProfile("too-few.example", 7, 0)
            )
        )
        try { assertEquals(1, ThreatKnowledgeGraph.learnedProfileCount()) }
        finally { ThreatKnowledgeGraph.updateObservations(emptyList()) }
    }

    @Test fun nonSocialProviderHasNoInventedPlatformAttribution() {
        val evidence = ThreatKnowledgeGraph.inspect("cdn.doubleclick.net")
        assertNull(evidence?.platform)
        assertEquals(
            listOf("proveedor: doubleclick.net", "dominio consultado: cdn.doubleclick.net"),
            evidence?.knowledgePath
        )
    }

}
