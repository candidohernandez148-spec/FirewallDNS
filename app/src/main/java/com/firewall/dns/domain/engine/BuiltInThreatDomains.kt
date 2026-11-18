package com.firewall.dns.domain.engine

/**
 * Única fuente de dominios semilla para el motor DNS y las herramientas de compatibilidad.
 * Estas reglas se incorporan al snapshot atómico del repositorio y respetan las excepciones.
 */
object BuiltInThreatDomains {
    val domains: List<String> = listOf(
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "google-analytics.com",
        "adservice.google.com",
        "adsrvr.org",
        "adnxs.com",
        "taboola.com",
        "outbrain.com",
        "criteo.com",
        "scorecardresearch.com",
        "quantserve.com",
        "moatads.com",
        "amazon-adsystem.com",
        "ads.facebook.com",
        "pixel.facebook.com",
        "analytics.facebook.com",
        "app-measurement.com",
        "appsflyer.com",
        "adjust.com",
        "branch.io",
        "mixpanel.com",
        "hotjar.com",
        "flurry.com",
        "unityads.unity3d.com",
        "applovin.com",
        "ironsrc.com",
        "mopub.com",
        "inmobi.com",
        "vungle.com"
    )
}
