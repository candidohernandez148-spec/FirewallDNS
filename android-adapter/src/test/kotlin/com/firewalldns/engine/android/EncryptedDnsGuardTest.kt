package com.firewalldns.engine.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EncryptedDnsGuardTest {
    @Test fun blocksCommonDotAndDoqPortsOnlyForTcpOrUdp() {
        assertTrue(EncryptedDnsGuard.shouldBlockPort(6, 853))
        assertTrue(EncryptedDnsGuard.shouldBlockPort(17, 853))
        assertTrue(EncryptedDnsGuard.shouldBlockPort(17, 784))
        assertTrue(EncryptedDnsGuard.shouldBlockPort(17, 8853))
        assertFalse(EncryptedDnsGuard.shouldBlockPort(6, 443))
        assertFalse(EncryptedDnsGuard.shouldBlockPort(17, 443))
        assertFalse(EncryptedDnsGuard.shouldBlockPort(1, 853))
    }

    @Test fun recognizesKnownDohEndpointsWithoutMatchingUnrelatedDomains() {
        assertTrue(EncryptedDnsGuard.isKnownDohEndpoint("dns.google"))
        assertTrue(EncryptedDnsGuard.isKnownDohEndpoint("resolver.dns.nextdns.io."))
        assertFalse(EncryptedDnsGuard.isKnownDohEndpoint("example.com"))
    }
}
