package com.fortguard.sdk

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.fortguard.sdk.core.JcaDeviceKey
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

/**
 * The device key lives in the Android KeyStore: generated in secure hardware (StrongBox when the phone
 * has it, otherwise the TEE), usable for signing, and impossible to export.
 */
internal object AndroidKeys {
    private const val ALIAS = "fortguard_device_key_v1"
    private const val PROVIDER = "AndroidKeyStore"

    fun loadOrCreate(): JcaDeviceKey {
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        val existing = ks.getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry
        if (existing != null) return JcaDeviceKey(existing.privateKey, existing.certificate.publicKey)
        val pair = generate(strongBox = Build.VERSION.SDK_INT >= 28)
        return JcaDeviceKey(pair.private, pair.public)
    }

    private fun generate(strongBox: Boolean): KeyPair {
        val builder = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
        if (strongBox && Build.VERSION.SDK_INT >= 28) builder.setIsStrongBoxBacked(true)
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        return try {
            kpg.initialize(builder.build())
            kpg.generateKeyPair()
        } catch (e: Exception) {
            // StrongBoxUnavailableException and friends: fall back to the TEE.
            if (strongBox) generate(strongBox = false) else throw e
        }
    }

    fun delete() {
        runCatching { KeyStore.getInstance(PROVIDER).apply { load(null) }.deleteEntry(ALIAS) }
    }
}
