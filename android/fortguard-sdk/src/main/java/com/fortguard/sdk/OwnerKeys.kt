package com.fortguard.sdk

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.fortguard.sdk.core.OwnerSigning
import com.fortguard.sdk.core.b64url
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * The owner key. It needs Android 11 or later, because only there can a key require a fingerprint or face
 * unlock (never a PIN). After the owner confirms with biometrics, the key can sign for WINDOW_S seconds,
 * then it refuses until the owner confirms again. The app never sees fingerprint data.
 */
internal object OwnerKeys {
    const val ALIAS = "fortguard_owner_key_v1"
    const val WINDOW_S = 600
    private const val PROVIDER = "AndroidKeyStore"

    val supported: Boolean get() = Build.VERSION.SDK_INT >= 30

    /** Creates the key if needed. Call only after the owner has enrolled a fingerprint or face. */
    fun create() {
        if (!supported) return
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        if (ks.containsAlias(ALIAS)) return
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        kpg.initialize(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(WINDOW_S, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
                .build()
        )
        kpg.generateKeyPair()
    }

    /** The owner's proof for one batch, or null when the window is closed or there is no key. */
    fun proofFor(payload: Map<String, Any?>): Map<String, Any?>? {
        if (!supported) return null
        return try {
            val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
            val entry = ks.getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry ?: return null
            val signature = Signature.getInstance("SHA256withECDSA").apply {
                initSign(entry.privateKey)
                update(OwnerSigning.signingBytes(payload))
            }
            mapOf("public_key" to b64url(entry.certificate.publicKey.encoded), "signature" to b64url(signature.sign()))
        } catch (e: Exception) {
            null // window closed, key invalidated by a new fingerprint, or not created: send without a proof
        }
    }

    fun delete() {
        runCatching { KeyStore.getInstance(PROVIDER).apply { load(null) }.deleteEntry(ALIAS) }
    }
}
