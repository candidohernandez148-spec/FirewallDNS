package com.firewalldns.engine.android

import org.junit.Assert.assertEquals
import org.junit.Test

class FirestackSocketBindingTest {
    @Test
    fun bindsToPhysicalNetworkBeforeProtectingAgainstVpnLoop() {
        val events = mutableListOf<String>()
        var bindingResult: Boolean? = null
        var protectionResult: Boolean? = null

        bindThenProtectSocket(
            bindPhysicalNetwork = { events += "bind" },
            protectFromVpn = {
                events += "protect"
                true
            },
            onBindingResult = { bindingResult = it },
            onProtectionResult = { protectionResult = it },
        )

        assertEquals(listOf("bind", "protect"), events)
        assertEquals(true, bindingResult)
        assertEquals(true, protectionResult)
    }

    @Test
    fun stillProtectsSocketWhenPhysicalNetworkBindingFails() {
        val events = mutableListOf<String>()
        var bindingResult: Boolean? = null
        var protectionResult: Boolean? = null

        bindThenProtectSocket(
            bindPhysicalNetwork = {
                events += "bind"
                error("network handover")
            },
            protectFromVpn = {
                events += "protect"
                true
            },
            onBindingResult = { bindingResult = it },
            onProtectionResult = { protectionResult = it },
        )

        assertEquals(listOf("bind", "protect"), events)
        assertEquals(false, bindingResult)
        assertEquals(true, protectionResult)
    }

    @Test
    fun reportsProtectionFailureWithoutThrowingFromBridgeCallback() {
        var protectionResult: Boolean? = null

        bindThenProtectSocket(
            bindPhysicalNetwork = {},
            protectFromVpn = { false },
            onBindingResult = {},
            onProtectionResult = { protectionResult = it },
        )

        assertEquals(false, protectionResult)
    }

    @Test
    fun boundsFirestackDomainMetadataAndDropsOversizedEntries() {
        val domains = (1..24).joinToString(",") { "host$it.example" }
        assertEquals(16, parseFirestackDomainMetadata(domains).size)
        assertEquals(
            listOf("ads.example", "tracker.example"),
            parseFirestackDomainMetadata(" ads.example,, tracker.example "),
        )
        assertEquals(emptyList<String>(), parseFirestackDomainMetadata("x".repeat(254)))
    }

    @Test
    fun rejectsOverlongFirestackEndpoints() {
        assertEquals(null, parseFirestackEndpoint("192.0.2.1:443".repeat(20), false))
    }

    @Test
    fun recognizesFirestackRdnsBlocklistSentinelsForIpv4AndIpv6() {
        assertEquals(true, isFirestackRdnsBlocklistAddress("0.0.0.0"))
        assertEquals(true, isFirestackRdnsBlocklistAddress("::"))
        assertEquals(false, isFirestackRdnsBlocklistAddress("203.0.113.25"))
        assertEquals(false, isFirestackRdnsBlocklistAddress("2001:db8::25"))
    }

}
