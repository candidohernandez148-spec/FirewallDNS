package com.firewall.dns.domain.engine

import java.net.URI

/**
 * Only accepts HTTPS list sources without embedded credentials or non-standard ports.
 * Redirects are intentionally handled as errors by the downloader to prevent HTTPS downgrade.
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
