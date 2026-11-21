package com.firewalldns.engine.dns

import java.io.Closeable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsExchangeCancellationTest {
    @Test
    fun cancellationWaitsUntilSocketProtectionCompletes() {
        val cancellation = DnsExchangeCancellation()
        val socket = TrackingCloseable()
        assertTrue(cancellation.register(socket))

        val protectionStarted = CountDownLatch(1)
        val finishProtection = CountDownLatch(1)
        val protectionResult = AtomicReference<Boolean?>(null)
        val protector = Thread {
            protectionResult.set(
                cancellation.protectSocket(socket) {
                    protectionStarted.countDown()
                    check(finishProtection.await(2, TimeUnit.SECONDS))
                    true
                },
            )
        }
        protector.start()
        assertTrue(protectionStarted.await(2, TimeUnit.SECONDS))

        val cancellationStarted = CountDownLatch(1)
        val cancellationFinished = CountDownLatch(1)
        val canceller = Thread {
            cancellationStarted.countDown()
            cancellation.cancel()
            cancellationFinished.countDown()
        }
        canceller.start()
        assertTrue(cancellationStarted.await(2, TimeUnit.SECONDS))
        assertFalse(cancellationFinished.await(50, TimeUnit.MILLISECONDS))

        finishProtection.countDown()
        assertTrue(cancellationFinished.await(2, TimeUnit.SECONDS))
        protector.join(2_000)
        canceller.join(2_000)

        assertEquals(true, protectionResult.get())
        assertTrue(cancellation.isCancelled)
        assertTrue(socket.closed.get())
    }

    @Test
    fun cancelledExchangeDoesNotAttemptSocketProtection() {
        val cancellation = DnsExchangeCancellation()
        val socket = TrackingCloseable()
        assertTrue(cancellation.register(socket))
        cancellation.cancel()

        val protectorCalled = AtomicBoolean(false)
        val result = cancellation.protectSocket(socket) {
            protectorCalled.set(true)
            true
        }

        assertNull(result)
        assertFalse(protectorCalled.get())
        assertTrue(socket.closed.get())
    }

    private class TrackingCloseable : Closeable {
        val closed = AtomicBoolean(false)
        override fun close() {
            closed.set(true)
        }
    }
}
