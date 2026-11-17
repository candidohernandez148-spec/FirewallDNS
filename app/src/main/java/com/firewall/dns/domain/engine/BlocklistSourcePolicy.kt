package com.firewall.dns.domain.engine

import java.net.URI

/**
 * Accepts only HTTPS list sources without embedded credentials, fragments or custom ports.
 * Redirects are rejected by the downloader to prevent HTTPS downgrade.
 */
object BlocklistSourcePolicy {
    fun isAllowed(rawUrl: String): Boolean {
        val uri = runCatching { URI(rawUrl.trim()) }.getOrNull() ?: return false
        return uri.scheme.equals("https", ignoreCase = true) &&
            !uri.host.isNullOrBlank() &&
            uri.userInfo == null &&
            (uri.port == -1 || uri.port == 443) &&
            uri.fragment == null
    }
}
