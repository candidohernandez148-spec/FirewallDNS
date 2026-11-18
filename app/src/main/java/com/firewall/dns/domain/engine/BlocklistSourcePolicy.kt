package com.firewall.dns.domain.engine

import java.net.URI

/**
 * Accepts only HTTPS list sources without embedded credentials, fragments or custom ports.
 * Redirects are rejected by the downloader to prevent HTTPS downgrade.
 */
object BlocklistSourcePolicy {
    fun canonicalize(rawUrl: String): String? {
        val uri = runCatching { URI(rawUrl.trim()).normalize() }.getOrNull() ?: return null
        if (!uri.scheme.equals("https", ignoreCase = true) ||
            uri.host.isNullOrBlank() || uri.userInfo != null ||
            (uri.port != -1 && uri.port != 443) || uri.fragment != null
        ) return null
        val host = uri.host.lowercase()
        val path = uri.rawPath.orEmpty()
        val query = uri.rawQuery?.let { "?" + it }.orEmpty()
        return "https://" + host + path + query
    }

    fun isAllowed(rawUrl: String): Boolean = canonicalize(rawUrl) != null
}
