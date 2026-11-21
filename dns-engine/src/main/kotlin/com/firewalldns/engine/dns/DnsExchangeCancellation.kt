package com.firewalldns.engine.dns

import java.io.Closeable

/**
 * Per-exchange cancellation scope. Cancelling closes the active socket to unblock
 * UDP receive and TCP connect/read. Create one instance per exchange.
 *
 * Socket protection is serialized with cancellation: a concurrent close must not
 * make VpnService.protect() report a false failure for an already-cancelled exchange.
 */
class DnsExchangeCancellation {
    private val lock = Any()
    @Volatile private var cancelled = false
    private var activeSocket: Closeable? = null

    val isCancelled: Boolean get() = cancelled

    fun cancel() {
        val socketToClose = synchronized(lock) {
            if (cancelled) {
                null
            } else {
                cancelled = true
                activeSocket.also { activeSocket = null }
            }
        }
        runCatching { socketToClose?.close() }
    }

    internal fun register(socket: Closeable): Boolean = synchronized(lock) {
        if (cancelled) return@synchronized false
        activeSocket = socket
        true
    }

    /**
     * Runs the short protect operation while cancellation is excluded from
     * closing this socket. Returns null when the exchange was already cancelled
     * or the socket is no longer the active exchange socket.
     */
    internal fun protectSocket(socket: Closeable, protect: () -> Boolean): Boolean? =
        synchronized(lock) {
            if (cancelled || activeSocket !== socket) null else protect()
        }

    internal fun unregister(socket: Closeable) {
        synchronized(lock) {
            if (activeSocket === socket) activeSocket = null
        }
    }
}
