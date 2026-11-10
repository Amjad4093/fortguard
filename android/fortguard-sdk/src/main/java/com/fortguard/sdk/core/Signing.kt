package com.fortguard.sdk.core

import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.util.Base64

/** The device's signing key. On Android it lives in the hardware-backed Android KeyStore. */
interface DeviceKey {
    /** X.509 SubjectPublicKeyInfo (DER) of the P-256 public key. */
    val publicKeySpki: ByteArray

    /** ECDSA P-256 with SHA-256, DER-encoded signature. */
    fun sign(data: ByteArray): ByteArray
}

/** Works with any JCA EC key: the Android KeyStore key on a phone, a software key in tests. */
class JcaDeviceKey(private val privateKey: PrivateKey, publicKey: PublicKey) : DeviceKey {
    override val publicKeySpki: ByteArray = publicKey.encoded

    override fun sign(data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }
}

/** The owner key signs only this: the batch body without its own signatures. Matches the server. */
object OwnerSigning {
    const val CONTEXT = "fortguard.owner-proof.v1\n"

    fun signingBytes(payload: Map<String, Any?>): ByteArray =
        (CONTEXT + CanonicalJson.encode(payload.filterKeys { it != "signature" && it != "owner_proof" })).toByteArray(Charsets.UTF_8)
}

object TelemetrySigning {
    /** Domain separation, must match the server's TELEMETRY_CONTEXT. */
    const val CONTEXT = "fortguard.telemetry.v1\n"

    fun signingBytes(payload: Map<String, Any?>): ByteArray =
        (CONTEXT + CanonicalJson.encode(payload.filterKeys { it != "signature" })).toByteArray(Charsets.UTF_8)

    /** Returns a copy of the payload with "signature" added. */
    fun sign(payload: Map<String, Any?>, key: DeviceKey): Map<String, Any?> {
        val signature = b64url(key.sign(signingBytes(payload)))
        return LinkedHashMap(payload).apply { put("signature", signature) }
    }
}

fun b64url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

object Ids {
    private val rng = SecureRandom()
    private const val ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

    /** prefix + n random characters; always matches the server's ID pattern. */
    fun random(prefix: String, n: Int): String {
        val sb = StringBuilder(prefix)
        repeat(n) { sb.append(ALPHABET[rng.nextInt(ALPHABET.length)]) }
        return sb.toString()
    }
}
