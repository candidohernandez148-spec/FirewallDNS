package com.firewall.dns.data.local

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DomainObservationPolicyTest {
    @Test
    fun normalizesValidDnsNames() {
        assertEquals("ads.example.com", DomainObservationPolicy.normalize(" ADS.Example.COM. "))
    }

    @Test
    fun acceptsOnlyInternallyConsistentObservationSummaries() {
        assertEquals(
            true,
            DomainObservationPolicy.isValidSummary("ads.example.com", 4L, 2L, 100L, 200L)
        )
        assertEquals(
            false,
            DomainObservationPolicy.isValidSummary("ads.example.com", -1L, 2L, 100L, 200L)
        )
        assertEquals(
            false,
            DomainObservationPolicy.isValidSummary("ads.example.com", 4L, 2L, 201L, 200L)
        )
        assertEquals(
            false,
            DomainObservationPolicy.isValidSummary("ADS.example.com", 4L, 2L, 100L, 200L)
        )
    }

    @Test
    fun rejectsMalformedOrNonDnsInput() {
        assertNull(DomainObservationPolicy.normalize(""))
        assertNull(DomainObservationPolicy.normalize("localhost"))
        assertNull(DomainObservationPolicy.normalize("bad..example.com"))
        assertNull(DomainObservationPolicy.normalize("https://example.com/path"))
        assertNull(DomainObservationPolicy.normalize("-bad.example.com"))
    }
}
