package com.firewalldns.engine.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsPortGuardTest {
    @Test fun blocksHardCodedIpv4AndIpv6ResolversOnDnsPort() {
        assertTrue(DnsPortGuard.shouldBlock(17, "8.8.8.8", 53))
        assertTrue(DnsPortGuard.shouldBlock(6, "1.1.1.1", 53))
        assertTrue(DnsPortGuard.shouldBlock(17, "2806:370:80d0:4::a", 53))
        assertTrue(DnsPortGuard.shouldBlock(6, "192.168.1.254", 53))
    }

    @Test fun permitsOnlyTheVirtualDnsEndpointsAndNonDnsPorts() {
        assertFalse(DnsPortGuard.shouldBlock(17, "10.10.10.1", 53))
        assertFalse(DnsPortGuard.shouldBlock(6, "fd00:10:10::1", 53))
        assertFalse(DnsPortGuard.shouldBlock(6, "8.8.8.8", 443))
        assertFalse(DnsPortGuard.shouldBlock(1, "8.8.8.8", 53))
    }
}
