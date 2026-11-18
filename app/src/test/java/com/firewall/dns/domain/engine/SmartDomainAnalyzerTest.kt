package com.firewall.dns.domain.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SmartDomainAnalyzerTest {

    @Test
    fun detectsAdSubdomainUnderGoogleWithoutWhitelistingWholeGoogleDomain() {
        val result = SmartDomainAnalyzer.evaluate("ads.google.com", emptyMap())
        assertTrue(result?.first == true)
    }

    @Test
    fun learnedWeightsUseOnlyTheExactFullyQualifiedDomain() {
        assertEquals(
            listOf("domain:ads.example.com"),
            SmartDomainAnalyzer.learnableTokens("ADS.Example.COM.")
        )
        assertTrue(
            SmartDomainAnalyzer.learnableTokens("ads.example.com")
                .none { it == "ads" || it == "example" || it == "com" }
        )
    }

    @Test
    fun doesNotBlockOrdinaryGoogleSubdomain() {
        assertNull(SmartDomainAnalyzer.evaluate("mail.google.com", emptyMap()))
    }

    @Test
    fun recognizesKnownAdTechProvidersWithoutDownloadedListEntries() {
        val adsRvr = SmartDomainAnalyzer.evaluate("sync.adsrvr.org", emptyMap())
        val scorecard = SmartDomainAnalyzer.evaluate("pixel.scorecardresearch.com", emptyMap())
        assertTrue(adsRvr?.first == true)
        assertTrue(scorecard?.first == true)
    }

    @Test
    fun doesNotBlockUnrecognizedOrdinaryDomainFromBaselineKnowledgeAlone() {
        assertNull(SmartDomainAnalyzer.evaluate("api.example.org", emptyMap()))
    }

    @Test
    fun keepsExplicitCoreSafeHostsOutOfSmartBlocking() {
        assertFalse(SmartDomainAnalyzer.evaluate("www.instagram.com", emptyMap())?.first == true)
    }

    @Test
    fun detectsMetaAdvertisingSubdomainsWithoutBlockingTheWholePlatform() {
        val facebookAds = SmartDomainAnalyzer.evaluate("ads.facebook.com", emptyMap())
        val instagramPixel = SmartDomainAnalyzer.evaluate("pixel.instagram.com", emptyMap())

        assertTrue(facebookAds?.first == true)
        assertTrue(facebookAds?.second?.contains("Publicidad Meta") == true)
        assertTrue(instagramPixel?.first == true)
        assertTrue(instagramPixel?.second?.contains("Publicidad Meta") == true)
        assertNull(SmartDomainAnalyzer.evaluate("api.facebook.com", emptyMap()))
        assertFalse(SmartDomainAnalyzer.evaluate("www.instagram.com", emptyMap())?.first == true)
    }

    @Test
    fun detectsTikTokAdvertisingAndMeasurementSubdomains() {
        val ads = SmartDomainAnalyzer.evaluate("ads.tiktok.com", emptyMap())
        val analytics = SmartDomainAnalyzer.evaluate("analytics.tiktok.com", emptyMap())

        assertTrue(ads?.first == true)
        assertTrue(ads?.second?.contains("Publicidad TikTok") == true)
        assertTrue(analytics?.first == true)
        assertTrue(analytics?.second?.contains("Medición TikTok") == true)
        assertNull(SmartDomainAnalyzer.evaluate("www.tiktok.com", emptyMap()))
    }

}
