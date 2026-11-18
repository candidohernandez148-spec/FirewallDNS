package com.firewall.dns.domain.engine

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
    fun doesNotBlockOrdinaryGoogleSubdomain() {
        assertNull(SmartDomainAnalyzer.evaluate("mail.google.com", emptyMap()))
    }

    @Test
    fun keepsExplicitCoreSafeHostsOutOfSmartBlocking() {
        assertFalse(SmartDomainAnalyzer.evaluate("www.instagram.com", emptyMap())?.first == true)
    }
}
