package com.firewall.dns.domain.engine

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.security.interfaces.RSAPublicKey

data class ThreatFeedSignatureConfig(
    val signatureUrl: String,
    val publicKeyX509: ByteArray
)

/**
 * Verifies detached RSA/SHA-256 signatures over the exact downloaded feed bytes.
 *
 * Public keys must be provisioned through a trusted release process (never downloaded
 * alongside the feed). A successful result proves possession of the corresponding
 * private key; it does not prove that the signed feed is safe or accurate.
 */
object ThreatFeedSignaturePolicy {
    private const val MIN_RSA_KEY_BITS = 2048

    /**
     * Returns false for missing/malformed keys, weak RSA keys, empty signatures,
     * invalid signatures, or any cryptographic verification error.
     *
     * [publicKeyX509] is the DER-encoded X.509 SubjectPublicKeyInfo public key.
     * [signatureBytes] is the raw detached signature over [payload].
     */
    fun verifyRsaSha256(
        payload: ByteArray,
        signatureBytes: ByteArray,
        publicKeyX509: ByteArray
    ): Boolean {
        if (payload.isEmpty() || signatureBytes.isEmpty() || publicKeyX509.isEmpty()) return false

        return try {
            val publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(X509EncodedKeySpec(publicKeyX509)) as? RSAPublicKey
                ?: return false
            if (publicKey.modulus.bitLength() < MIN_RSA_KEY_BITS) return false

            Signature.getInstance("SHA256withRSA").run {
                initVerify(publicKey)
                update(payload)
                verify(signatureBytes)
            }
        } catch (_: Exception) {
            false
        }
    }
}
