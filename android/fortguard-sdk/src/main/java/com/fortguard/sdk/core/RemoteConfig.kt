package com.fortguard.sdk.core

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * What the bank's signed configuration lets the SDK collect. Every kind is on until a configuration
 * with a valid signature says otherwise.
 */
data class CollectionPolicy(
    val version: Long = 0,
    val touch: Boolean = true,
    val keys: Boolean = true,
    val motion: Boolean = true,
    val sensors: Boolean = true,
    val location: Boolean = true,
    val flushIntervalMs: Long = 5_000,
) {
    companion object {
        /** Null when anything is missing or of the wrong type: a malformed configuration is never half-applied. */
        fun from(config: Map<String, Any?>): CollectionPolicy? {
            val collect = config["collect"] as? Map<*, *> ?: return null
            val version = config["version"] as? Long ?: return null
            val flush = config["flush_interval_ms"] as? Long ?: return null
            fun kind(name: String) = collect[name] as? Boolean
            return CollectionPolicy(
                version = version,
                touch = kind("touch") ?: return null,
                keys = kind("keys") ?: return null,
                motion = kind("motion") ?: return null,
                sensors = kind("sensors") ?: return null,
                location = kind("location") ?: return null,
                flushIntervalMs = flush.coerceIn(1_000, 60_000),
            )
        }
    }
}

/** Checks the server's signature on a configuration (ES256 over a context line plus canonical JSON). */
object ConfigSigning {
    /** Domain separation: a configuration signature is never valid as a telemetry signature, or the reverse. */
    const val CONTEXT = "fortguard.config.v1\n"

    fun signingBytes(config: Map<String, Any?>): ByteArray =
        (CONTEXT + CanonicalJson.encode(config)).toByteArray(Charsets.UTF_8)

    /** [publicKeySpki] is the DER SubjectPublicKeyInfo the back office shows under Data collection. */
    fun verify(config: Map<String, Any?>, signatureB64: String, publicKeySpki: ByteArray): Boolean = runCatching {
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKeySpki))
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(signingBytes(config))
            verify(unb64url(signatureB64))
        }
    }.getOrDefault(false)

    fun unb64url(text: String): ByteArray = Base64.getUrlDecoder().decode(text)
}

/** Where the SDK remembers the key it trusts and the last configuration it accepted, across app starts. */
interface ConfigMemory {
    fun get(name: String): String?
    fun put(name: String, value: String)
}
