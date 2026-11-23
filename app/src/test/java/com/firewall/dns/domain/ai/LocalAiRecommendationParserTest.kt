package com.firewall.dns.domain.ai

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class LocalAiRecommendationParserTest {

    @Test
    fun parsesStructuredAdRecommendation() {
        val result = LocalAiRecommendationParser.parse(
            """{"summary":"Publicidad detectada","recommendations":[{"domain":"ADS.Example.com.","category":"ADVERTISING","action":"BLOCK","confidence":0.97,"reason":"Patrón de anuncios"}]}"""
        )
        assertNotNull(result)
        assertEquals("ads.example.com", result!!.recommendations.single().domain)
        assertEquals(LocalAiSuggestedAction.BLOCK, result.recommendations.single().action)
        assertEquals(0.97f, result.recommendations.single().confidence)
        assertEquals("Patrón de anuncios", result.recommendations.single().explanation)
    }

    @Test
    fun discardsInvalidOrOutOfRangeRecommendations() {
        val result = LocalAiRecommendationParser.parse(
            """{"summary":"Prueba","recommendations":[
                {"domain":"bad domain","category":"ADVERTISING","action":"BLOCK","confidence":0.99},
                {"domain":"ads.example.com","category":"ADVERTISING","action":"BLOCK","confidence":1.5},
                {"domain":"safe.example.com","category":"OTHER","action":"BLOCK","confidence":0.99},
                {"domain":"track.example.com","category":"TRACKER","action":"OBSERVE","confidence":0.7}
            ]}"""
        )
        assertNotNull(result)
        assertEquals(1, result!!.recommendations.size)
        assertEquals("track.example.com", result.recommendations.single().domain)
    }

    @Test
    fun parsesJsonAfterModelReasoningPreamble() {
        val raw = "<think>Analizo indicadores.</think> {\"summary\":\"Rastreo detectado\",\"recommendations\":[{\"domain\":\"track.example.com\",\"category\":\"TRACKER\",\"action\":\"BLOCK\",\"confidence\":0.96}]}"
        val result = LocalAiRecommendationParser.parse(raw)
        assertNotNull(result)
        assertEquals("track.example.com", result!!.recommendations.single().domain)
    }

    @Test
    fun rejectsNonJsonAndMissingRecommendationArray() {
        assertNull(LocalAiRecommendationParser.parse("not json"))
        assertNull(LocalAiRecommendationParser.parse("""{"summary":"empty"}"""))
    }
}
