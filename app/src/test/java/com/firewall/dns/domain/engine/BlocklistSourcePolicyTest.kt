package com.firewall.dns.domain.engine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Test

class BlocklistSourcePolicyTest {
    @Test fun acceptsHttpsDefaultAnd443Ports() {
        assertTrue(BlocklistSourcePolicy.isAllowed("https://example.com/list.txt"))
        assertTrue(BlocklistSourcePolicy.isAllowed("HTTPS://lists.example.org:443/ads.txt"))
    }

    @Test fun canonicalizesDuplicateHttpsUrls() {
        assertEquals(
            "https://example.com/list.txt",
            BlocklistSourcePolicy.canonicalize("HTTPS://EXAMPLE.COM:443/list.txt")
        )
        assertEquals(
            "https://example.com/list.txt",
            BlocklistSourcePolicy.canonicalize("https://example.com/a/../list.txt")
        )
    }

    @Test fun rejectsCleartextAndCustomPorts() {
        assertFalse(BlocklistSourcePolicy.isAllowed("http://example.com/list.txt"))
        assertFalse(BlocklistSourcePolicy.isAllowed("https://example.com:8443/list.txt"))
        assertFalse(BlocklistSourcePolicy.isAllowed("ftp://example.com/list.txt"))
    }

    @Test fun rejectsCredentialsFragmentsAndMalformedUrls() {
        assertFalse(BlocklistSourcePolicy.isAllowed("https://user:pass@example.com/list.txt"))
        assertFalse(BlocklistSourcePolicy.isAllowed("https://example.com/list.txt#rules"))
        assertFalse(BlocklistSourcePolicy.isAllowed("https:///missing-host"))
        assertFalse(BlocklistSourcePolicy.isAllowed("not a url"))
    }
}
