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
    /**
     * Public key (DER SubjectPublicKeyInfo) the bank's configuration must be signed with. Build it into a
     * production app. When null the SDK trusts the first key the server shows and remembers it.
     */
    private val configKey: ByteArray? = null,
    private val configMemory: ConfigMemory? = null,
) {
    @Volatile var consentBehavioral: Boolean = true
        set(value) { field = value; buffer.enabled = value; if (!value) buffer.clear() }

    /** Whether the customer agreed to share approximate location. Null until the app has asked. */
    @Volatile var consentLocation: Boolean? = null

    /** The published wording the customer accepted: group ("behavioural", "location") to (language, version). */
    @Volatile var consentTexts: Map<String, Pair<String, Long>> = emptyMap()

    /** What the bank's signed configuration allows. Everything is on until a valid configuration says otherwise. */
    @Volatile var policy: CollectionPolicy = CollectionPolicy()
        private set

    /** Called after a configuration with a valid signature changed the policy. */
    @Volatile var onPolicy: ((CollectionPolicy) -> Unit)? = null

    init {
        restoreConfig()
    }

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
        // The server names the configuration version it is on with every batch; fetch it when ours differs.
        val serverVersion = r.body["config_version"] as? Long
        if (r.status == 202 && serverVersion != null && serverVersion != policy.version) {
            runCatching { refreshConfig() }.onFailure { log("configuration not refreshed: ${it.message}") }
        }
        Outcome(r.status == 202, r.describe(), r)
    }

    /**
     * Fetches the bank's configuration and applies it when, and only when, its signature verifies against
     * the trusted key and it is not older than the one in use. On any failure the current policy stays.
     */
    fun refreshConfig(): Outcome = synchronized(lock) {
        val r = api.get("/v1/config")
        if (!r.ok) return Outcome(false, "configuration: ${r.describe()}", r)
        @Suppress("UNCHECKED_CAST")
        val config = r.body["config"] as? Map<String, Any?> ?: return Outcome(false, "configuration: malformed reply", r)
        val signature = r.body["signature"] as? String ?: return Outcome(false, "configuration: no signature", r)
        accept(config, signature, remember = true)
    }

    private fun accept(config: Map<String, Any?>, signature: String, remember: Boolean): Outcome {
        val key = trustedKey() ?: return Outcome(false, "configuration: no key to check the signature with")
        if (!ConfigSigning.verify(config, signature, key)) {
            log("configuration refused: the signature does not verify")
            return Outcome(false, "configuration refused: the signature does not verify")
        }
        val next = CollectionPolicy.from(config) ?: return Outcome(false, "configuration: malformed")
        if (next.version < policy.version) return Outcome(false, "configuration refused: older than the one in use")
        if (remember) configMemory?.put(MEMORY_CONFIG, CanonicalJson.encode(mapOf("config" to config, "signature" to signature)))
        if (next != policy) {
            policy = next
            buffer.allowTouch = next.touch
            buffer.allowKeys = next.keys
            buffer.allowMotion = next.motion
            buffer.allowSensors = next.sensors
            log("configuration version ${next.version} applied")
            onPolicy?.invoke(next)
        }
        return Outcome(true, "configuration version ${next.version}")
    }

    private fun trustedKey(): ByteArray? {
        configKey?.let { return it }
        configMemory?.get(MEMORY_KEY)?.let { saved -> runCatching { ConfigSigning.unb64url(saved) }.getOrNull()?.let { return it } }
        val text = api.get("/v1/config/key").body["public_key"] as? String ?: return null
        val bytes = runCatching { ConfigSigning.unb64url(text) }.getOrNull() ?: return null
        configMemory?.put(MEMORY_KEY, text)
        log("no configuration key was built in: trusting the first one the server showed")
        return bytes
    }

    /** Applies the last accepted configuration at start, before the network is reached. It is verified again. */
    private fun restoreConfig() {
        if (configKey == null && configMemory?.get(MEMORY_KEY) == null) return   // never ask the network from a constructor
        val saved = configMemory?.get(MEMORY_CONFIG) ?: return
        runCatching {
            @Suppress("UNCHECKED_CAST")
            val doc = MiniJson.parse(saved) as Map<String, Any?>
            @Suppress("UNCHECKED_CAST")
            accept(doc["config"] as Map<String, Any?>, doc["signature"] as String, remember = false)
        }
    }

    private fun send(d: EventBuffer.Drained): ApiClient.Response {
        val payload = linkedMapOf<String, Any?>(
            "session_id" to sessionId,
            "device_guid" to deviceGuid,
            "app_id" to appId,
            "timestamp_ms" to clock(),
            "nonce" to Ids.random("n_", 20),
            "seq" to seq++,
            "consent" to consentBlock(),
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

    /** The customer's answers and, when the app showed published wording, which version they accepted. */
    internal fun consentBlock(): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        out["behavioral"] = consentBehavioral
        consentLocation?.let { out["location"] = it }
        val texts = consentTexts
        if (texts.isNotEmpty()) {
            out["texts"] = texts.mapValues { (_, accepted) -> mapOf("lang" to accepted.first, "version" to accepted.second) }
        }
        return out
    }

    companion object {
        private const val MEMORY_KEY = "config_key"
        private const val MEMORY_CONFIG = "config_signed"

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
