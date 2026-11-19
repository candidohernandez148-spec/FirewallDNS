package com.firewall.dns.domain.engine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SmartDomainAnalyzerTest {
    @Test fun detectsAdSubdomainUnderGoogleWithoutWhitelistingWholeGoogleDomain() {
        assertTrue(SmartDomainAnalyzer.evaluate("ads.google.com")?.first == true)
    }

    @Test fun doesNotBlockOrdinaryGoogleSubdomain() {
        assertNull(SmartDomainAnalyzer.evaluate("mail.google.com"))
    }

    @Test fun recognizesKnownAdTechProvidersWithoutDownloadedListEntries() {
        assertTrue(SmartDomainAnalyzer.evaluate("sync.adsrvr.org")?.first == true)
        assertTrue(SmartDomainAnalyzer.evaluate("pixel.scorecardresearch.com")?.first == true)
    }

    @Test fun doesNotBlockUnrecognizedOrdinaryDomainFromBaselineKnowledgeAlone() {
        assertNull(SmartDomainAnalyzer.evaluate("api.example.org"))
    }

    @Test fun keepsExplicitCoreSafeHostsOutOfSmartBlocking() {
        assertFalse(SmartDomainAnalyzer.evaluate("www.instagram.com")?.first == true)
    }

    @Test fun detectsMetaAdvertisingSubdomainsWithoutBlockingTheWholePlatform() {
        val facebookAds = SmartDomainAnalyzer.evaluate("ads.facebook.com")
        val instagramPixel = SmartDomainAnalyzer.evaluate("pixel.instagram.com")
        assertTrue(facebookAds?.first == true)
        assertTrue(facebookAds?.second?.contains("Publicidad Meta") == true)
        assertTrue(instagramPixel?.first == true)
        assertTrue(instagramPixel?.second?.contains("Publicidad Meta") == true)
        assertNull(SmartDomainAnalyzer.evaluate("api.facebook.com"))
        assertFalse(SmartDomainAnalyzer.evaluate("www.instagram.com")?.first == true)
    }

    @Test fun detectsTikTokAdvertisingAndMeasurementSubdomains() {
        val ads = SmartDomainAnalyzer.evaluate("ads.tiktok.com")
        val analytics = SmartDomainAnalyzer.evaluate("analytics.tiktok.com")
        assertTrue(ads?.first == true)
        assertTrue(ads?.second?.contains("Publicidad TikTok") == true)
        assertTrue(analytics?.first == true)
        assertTrue(analytics?.second?.contains("Medición TikTok") == true)
        assertNull(SmartDomainAnalyzer.evaluate("www.tiktok.com"))
    }
}
