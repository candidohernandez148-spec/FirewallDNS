package com.firewalldns.engine.android

import org.junit.Assert.assertEquals
import org.junit.Test

class FirestackNetworkHandoverTest {
    @Test
    fun updatesResolverBeforeRestartingSocketsOnNetworkChange() {
        val events = mutableListOf<String>()

        val result = updateAndRestartFirestackNetwork(
            updateResolver = {
                events += "resolver"
                true
            },
            networkChanged = true,
            restartStack = {
                events += "restart"
                true
            },
        )

        assertEquals(true, result)
        assertEquals(listOf("resolver", "restart"), events)
    }

    @Test
    fun doesNotRestartExistingFlowsWhenOnlyResolverConfigurationChanges() {
        val events = mutableListOf<String>()

        val result = updateAndRestartFirestackNetwork(
            updateResolver = {
                events += "resolver"
                true
            },
            networkChanged = false,
            restartStack = {
                events += "restart"
                true
            },
        )

        assertEquals(true, result)
        assertEquals(listOf("resolver"), events)
    }

    @Test
    fun doesNotRestartStackWhenResolverUpdateFails() {
        val events = mutableListOf<String>()

        val result = updateAndRestartFirestackNetwork(
            updateResolver = {
                events += "resolver"
                false
            },
            networkChanged = true,
            restartStack = {
                events += "restart"
                true
            },
        )

        assertEquals(false, result)
        assertEquals(listOf("resolver"), events)
    }

    @Test
    fun reportsRestartFailureSoVpnServiceCanRecover() {
        val events = mutableListOf<String>()

        val result = updateAndRestartFirestackNetwork(
            updateResolver = {
                events += "resolver"
                true
            },
            networkChanged = true,
            restartStack = {
                events += "restart"
                false
            },
        )

        assertEquals(false, result)
        assertEquals(listOf("resolver", "restart"), events)
    }
}
