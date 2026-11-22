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
    fun recognizesFirestackRdnsBlocklistSentinelsForIpv4AndIpv6() {
        assertEquals(true, isFirestackRdnsBlocklistAddress("0.0.0.0"))
        assertEquals(true, isFirestackRdnsBlocklistAddress("::"))
        assertEquals(false, isFirestackRdnsBlocklistAddress("203.0.113.25"))
        assertEquals(false, isFirestackRdnsBlocklistAddress("2001:db8::25"))
    }

}
