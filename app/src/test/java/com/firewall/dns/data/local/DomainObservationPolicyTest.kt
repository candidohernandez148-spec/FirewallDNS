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
    fun rejectsMalformedOrNonDnsInput() {
        assertNull(DomainObservationPolicy.normalize(""))
        assertNull(DomainObservationPolicy.normalize("localhost"))
        assertNull(DomainObservationPolicy.normalize("bad..example.com"))
        assertNull(DomainObservationPolicy.normalize("https://example.com/path"))
        assertNull(DomainObservationPolicy.normalize("-bad.example.com"))
    }
}
