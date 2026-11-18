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

    @Test fun ordinaryDomainsRemainAllowed() {
        assertNull(SmartDecisionEngine.evaluate("api.example.org"))
        assertNull(SmartDecisionEngine.evaluate("mail.google.com"))
    }

    @Test fun learnedAllowSignalPreventsHeuristicBlock() {
        val result = SmartDecisionEngine.evaluate("ads.example.org", mapOf("ads" to -2))
        assertEquals(SmartDecisionEngine.Level.OBSERVE, result?.level)
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
