package com.fortguard.sdk.core

data class AttestationRequest(
    val deviceGuid: String,
    val appId: String,
    val platform: String,
    val challenge: String,
    val publicKeyB64: String,
)

/** Produces the attestation token sent with enrollment. */
fun interface AttestationProvider {
    /** Returns the token, or throws with a readable message. Called on a background thread. */
    fun attest(request: AttestationRequest): String
}

/**
 * DEVELOPMENT ONLY. Asks the FortGuard server's dev endpoint to mint a simulated token. Works only
 * when the server runs with --dev. It proves the flow, not the device.
 */
class DevAttestationProvider(private val api: ApiClient, private val level: () -> String = { "STRONG" }) :
    AttestationProvider {
    override fun attest(request: AttestationRequest): String {
        val r = api.postJson("/v1/dev/attest", mapOf(
            "device_guid" to request.deviceGuid, "app_id" to request.appId, "platform" to request.platform,
            "challenge" to request.challenge, "public_key" to request.publicKeyB64, "level" to level(),
        ))
        if (!r.ok) throw IllegalStateException("dev attestation failed: ${r.describe()} (is the server running with --dev?)")
        return r.body["attestation"] as? String ?: throw IllegalStateException("dev attestation returned no token")
    }
}

/*
 * Production replacement (not built): Google Play Integrity.
 *
 *   1. requestHash = SHA-256(challenge + "." + SHA-256(publicKeySpki)), so the verdict is bound to this
 *      enrollment's challenge and to this key.
 *   2. StandardIntegrityManager.prepareIntegrityToken(cloudProjectNumber), then request(requestHash).
 *   3. Send the token as "attestation". The server's PlayIntegrityVerifier (also not built) decodes it
 *      with Google, checks the requestHash, the package name, the signing certificate and the device
 *      verdict, and maps it to STRONG / DEVICE / BASIC.
 *
 * Needs: the dependency com.google.android.play:integrity, a Google Cloud project linked in Play
 * Console, and the app distributed through Play (an internal test track is enough).
 */
