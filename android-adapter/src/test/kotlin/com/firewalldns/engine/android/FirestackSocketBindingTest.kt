package com.firewalldns.engine.android

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyDecision
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
        assertEquals(
            listOf("valid.example"),
            parseFirestackDomainMetadata("valid.example," + "x".repeat(4090) + ",tail.example"),
        )
    }

    @Test
    fun cnameInspectionOnlyRunsForEndpointAndServiceAliasQueryTypes() {
        listOf(1, 5, 28, 39, 64, 65).forEach {
            assertEquals(true, isCnameRelevantQueryType(it))
        }
        listOf(2, 6, 15, 16, 33, 255).forEach {
            assertEquals(false, isCnameRelevantQueryType(it))
        }
    }

    @Test
    fun blocksOnlyCnameAliasesThatMatchAnExistingBlockDecision() {
        val match = findBlockedCnameTarget(
            queriedDomain = "assets.site.example",
            targetsCsv = "assets.site.example,tracker.bad.example,cdn.site.example",
        ) { domain ->
            if (domain == "tracker.bad.example") {
                PolicyDecision(PolicyAction.BLOCK, "known_tracker_domain")
            } else {
                PolicyDecision(PolicyAction.ALLOW, "no_matching_rule")
            }
        }

        assertEquals("tracker.bad.example", match?.domain)
        assertEquals(PolicyAction.BLOCK, match?.decision?.action)
        assertEquals("known_tracker_domain", match?.decision?.reason)
    }

    @Test
    fun cnameObserveSignalsNeverBecomeBlocks() {
        val match = findBlockedCnameTarget(
            queriedDomain = "assets.site.example",
            targetsCsv = "assets.site.example,analytics.site.example",
        ) {
            PolicyDecision(PolicyAction.OBSERVE, "heuristic_signal")
        }

        assertEquals(null, match)
    }

    @Test
    fun cnameEvaluationSkipsOriginalNameAndInvalidMetadata() {
        val match = findBlockedCnameTarget(
            queriedDomain = "ASSETS.SITE.EXAMPLE.",
            targetsCsv = "assets.site.example,not a domain,",
        ) {
            PolicyDecision(PolicyAction.BLOCK, "test_block")
        }

        assertEquals(null, match)
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
