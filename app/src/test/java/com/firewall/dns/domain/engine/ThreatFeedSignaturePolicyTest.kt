package com.firewall.dns.domain.engine

import java.security.KeyPairGenerator
import java.security.Signature
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatFeedSignaturePolicyTest {
    private fun createKeyPair(bits: Int = 2048) =
        KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()

    private fun sign(payload: ByteArray, privateKey: java.security.PrivateKey): ByteArray =
        Signature.getInstance("SHA256withRSA").run {
            initSign(privateKey)
            update(payload)
            sign()
        }

    @Test
    fun acceptsSignatureFromPinnedRsaKey() {
        val payload = "||example.com^".toByteArray()
        val pair = createKeyPair()
        val signature = sign(payload, pair.private)

        assertTrue(
            ThreatFeedSignaturePolicy.verifyRsaSha256(
                payload,
                signature,
                pair.public.encoded
            )
        )
    }

    @Test
    fun rejectsModifiedPayload() {
        val pair = createKeyPair()
        val signature = sign("||example.com^".toByteArray(), pair.private)

        assertFalse(
            ThreatFeedSignaturePolicy.verifyRsaSha256(
                "||attacker.example^".toByteArray(),
                signature,
                pair.public.encoded
            )
        )
    }

    @Test
    fun rejectsSignatureFromDifferentKey() {
        val payload = "||example.com^".toByteArray()
        val signer = createKeyPair()
        val other = createKeyPair()

        assertFalse(
            ThreatFeedSignaturePolicy.verifyRsaSha256(
                payload,
                sign(payload, signer.private),
                other.public.encoded
            )
        )
    }

    @Test
    fun rejectsEmptyAndMalformedInputs() {
        val pair = createKeyPair()
        assertFalse(ThreatFeedSignaturePolicy.verifyRsaSha256(byteArrayOf(), byteArrayOf(1), pair.public.encoded))
        assertFalse(ThreatFeedSignaturePolicy.verifyRsaSha256(byteArrayOf(1), byteArrayOf(), pair.public.encoded))
        assertFalse(ThreatFeedSignaturePolicy.verifyRsaSha256(byteArrayOf(1), byteArrayOf(1), byteArrayOf(1, 2, 3)))
    }

    @Test
    fun rejectsRsaKeysSmallerThan2048Bits() {
        val weakPair = createKeyPair(bits = 1024)
        val payload = "||example.com^".toByteArray()

        assertFalse(
            ThreatFeedSignaturePolicy.verifyRsaSha256(
                payload,
                sign(payload, weakPair.private),
                weakPair.public.encoded
            )
        )
    }
}
