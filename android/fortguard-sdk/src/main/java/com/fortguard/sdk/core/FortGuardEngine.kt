package com.fortguard.sdk.core

/**
 * Platform-neutral heart of the SDK: enrollment, batching, signing and upload.
 *
 * Has no Android imports, so it compiles and runs on any JVM. The Android layer (FortGuard.kt) feeds it
 * events and supplies the hardware key and the environment checks.
 *
 * All network methods block. Call them from a background thread.
 */
class FortGuardEngine(
    private val api: ApiClient,
    val appId: String,
    val deviceGuid: String,
    private val key: DeviceKey,
    private val attestation: AttestationProvider,
    private val environment: () -> Map<String, Any?>,
    private val platform: String = "Android",
    private val clock: () -> Long = System::currentTimeMillis,
    private val log: (String) -> Unit = {},
    val buffer: EventBuffer = EventBuffer(),
    /** Returns the owner proof for a batch, or null when no owner window is open. Set by the Android layer. */
    private val ownerProof: ((Map<String, Any?>) -> Map<String, Any?>?)? = null,
    /** The customer this phone is used by (user_id, customer_name), when the app has identified them. */
    private val identity: (() -> Map<String, String>)? = null,
) {
    @Volatile var consentBehavioral: Boolean = true
        set(value) { field = value; buffer.enabled = value; if (!value) buffer.clear() }

    @Volatile var sessionId: String = Ids.random("sess_", 16)
        private set

    @Volatile var enrolledLevel: String? = null
        private set

    @Volatile var lastBatchJson: String? = null
        private set

    private var seq = 0
    private val lock = Any()

    data class Outcome(val ok: Boolean, val message: String, val response: ApiClient.Response? = null)

    val publicKeyB64: String get() = b64url(key.publicKeySpki)

    fun newSession(): String = synchronized(lock) {
        sessionId = Ids.random("sess_", 16)
        seq = 0
        buffer.clear()
        sessionId
    }

    /** Challenge, attestation, enrollment. Re-run with force=true after the level changes. */
    fun enroll(force: Boolean = false): Outcome = synchronized(lock) {
        if (enrolledLevel != null && !force) return Outcome(true, "already enrolled ($enrolledLevel)")
        val ch = api.postJson("/v1/devices/challenge", emptyMap())
        if (ch.status != 201) return Outcome(false, "challenge failed: ${ch.describe()}", ch)
        val challenge = ch.body["challenge"] as? String ?: return Outcome(false, "challenge missing", ch)
        val token = try {
            attestation.attest(AttestationRequest(deviceGuid, appId, platform, challenge, publicKeyB64))
        } catch (e: Exception) {
            return Outcome(false, e.message ?: "attestation failed")
        }
        val r = api.postJson("/v1/devices/enroll", mapOf(
            "device_guid" to deviceGuid, "app_id" to appId, "platform" to platform,
            "public_key" to publicKeyB64, "challenge" to challenge, "attestation" to token,
        ))
        if (r.status != 201) return Outcome(false, "enrollment failed: ${r.describe()}", r)
        enrolledLevel = r.body["integrity_level"] as? String
        log("enrolled, attestation level $enrolledLevel")
        Outcome(true, "enrolled ($enrolledLevel)", r)
    }

    /** Builds, signs and sends one batch. With force=false an empty buffer sends nothing. */
    fun flush(force: Boolean = false): Outcome = synchronized(lock) {
        val drained = buffer.drain()
        if (drained.isEmpty && !force) return Outcome(true, "nothing to send")
        if (enrolledLevel == null) {
            val e = enroll()
            if (!e.ok) return e
        }
        var r = send(drained)
        if (r.status == 401 && r.errorCode == "unknown_device") {
            log("server does not know this device (restarted?), enrolling again")
            enrolledLevel = null
            val e = enroll(force = true)
            if (!e.ok) return e
            r = send(drained)
        }
        if (r.status == 400 && r.errorCode == "stale_timestamp") {
            return Outcome(false, "this phone's clock differs from the server's by more than 5 minutes", r)
        }
        log("telemetry ${r.describe()}")
        Outcome(r.status == 202, r.describe(), r)
    }

    private fun send(d: EventBuffer.Drained): ApiClient.Response {
        val payload = linkedMapOf<String, Any?>(
            "session_id" to sessionId,
            "device_guid" to deviceGuid,
            "app_id" to appId,
            "timestamp_ms" to clock(),
            "nonce" to Ids.random("n_", 20),
            "seq" to seq++,
            "consent" to mapOf("behavioral" to consentBehavioral),
            "environment" to environment(),
            "touch_events" to d.touch,
            "key_events" to d.keys,
            "ui_events" to d.ui,
            "sensor_data" to LinkedHashMap<String, Any?>(d.extra).apply {
                put("accelerometer", d.accel)
                put("gyroscope", d.gyro)
            },
        )
        addIdentityThenProof(payload, identity, ownerProof)
        val signed = TelemetrySigning.sign(payload, key)
        val body = CanonicalJson.encode(signed)
        lastBatchJson = body
        return api.post("/v1/telemetry/stream", body)
    }

    companion object {
        /**
         * Identity goes in first. The owner proof covers every field except itself and the device signature,
         * so anything added after the proof makes the server refuse the batch (bad_owner_proof).
         */
        internal fun addIdentityThenProof(
            payload: MutableMap<String, Any?>,
            identity: (() -> Map<String, String>)?,
            ownerProof: ((Map<String, Any?>) -> Map<String, Any?>?)?,
        ) {
            identity?.invoke()?.forEach { (k, v) -> payload[k] = v }
            ownerProof?.invoke(payload)?.let { payload["owner_proof"] = it }
        }
    }
}
