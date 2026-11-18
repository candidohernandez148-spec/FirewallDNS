package com.firewall.dns.domain.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatFeedCatalogTest {
    @Test fun identifiesOfficialFeedCategories() {
        assertEquals(
            ThreatFeedCategory.PHISHING,
            ThreatFeedCatalog.categoryForUrl("https://phishing.army/download/phishing-army-adblock.txt")
        )
        assertEquals(
            ThreatFeedCategory.MALWARE_PHISHING,
            ThreatFeedCatalog.categoryForUrl("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt")
        )
        assertEquals(
            ThreatFeedCategory.ADS_TRACKING,
            ThreatFeedCatalog.categoryForUrl("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt")
        )
        assertEquals(
            ThreatFeedCategory.GENERAL,
            ThreatFeedCatalog.categoryForUrl("https://example.org/custom.txt")
        )
    }

    @Test fun matchesOnlyExactDomainOrSubdomains() {
        val domains = setOf("bad.example")
        assertTrue(ThreatFeedCatalog.matchesDomainOrParent("login.bad.example", domains))
        assertTrue(ThreatFeedCatalog.matchesDomainOrParent("bad.example", domains))
        assertFalse(ThreatFeedCatalog.matchesDomainOrParent("notbad.example", domains))
        assertFalse(ThreatFeedCatalog.matchesDomainOrParent("example", domains))
    }
}
