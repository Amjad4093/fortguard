package com.fortguard.sdk

import android.app.Activity
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.EditText
import com.fortguard.sdk.core.ApiClient
import com.fortguard.sdk.core.AttestationProvider
import com.fortguard.sdk.core.Counts
import com.fortguard.sdk.core.DevAttestationProvider
import com.fortguard.sdk.core.EventBuffer
import com.fortguard.sdk.core.Field
import com.fortguard.sdk.core.FortGuardEngine
import com.fortguard.sdk.core.Ids
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * FortGuard SDK for Android.
 *
 * ```
 * // Application.onCreate or the first Activity
 * FortGuard.init(context, FortGuard.Config(baseUrl = "https://risk.example.com", appId = BuildConfig.APPLICATION_ID))
 *
 * // each protected screen
 * override fun onResume() { super.onResume(); FortGuard.attach(this) }
 * override fun onPause()  { FortGuard.detach(this); super.onPause() }
 * FortGuard.watch(beneficiaryInput, Field.BENEFICIARY_ACCOUNT)
 *
 * // before the payment: send what is buffered, then give FortGuard.sessionId to your backend,
 * // which calls POST /v1/risk/evaluate with its own API key.
 * FortGuard.submit { outcome -> backend.pay(sessionId = FortGuard.sessionId) }
 * ```
 *
 * The SDK never reads what the user types. It records touch, the timing of edits, motion sensors and
 * device checks, signs each batch with a hardware key and sends it every few seconds.
 */
object FortGuard {

    data class Config(
        val baseUrl: String,
        val appId: String,
        /** DEVELOPMENT ONLY: get simulated attestation from a server running with --dev. */
        val devAttestation: Boolean = true,
        /** Attestation level the dev server should grant (STRONG, DEVICE, BASIC). Testing only. */
        val devAttestationLevel: () -> String = { "STRONG" },
        /** Lets a test app force environment flags. Never enable in a production build. */
        val allowDebugOverrides: Boolean = false,
        val flushIntervalMs: Long = 5_000,
        /** Production attestation (Play Integrity) goes here when it is built. */
        val attestationProvider: AttestationProvider? = null,
        /**
         * The bank's configuration-signing public key (DER SubjectPublicKeyInfo), from the back office's
         * Data collection page. Build it into a production app. When null the SDK trusts the first key the
         * server shows and remembers it, which is acceptable for a demo only.
         */
        val configPublicKey: ByteArray? = null,
    )

    data class Status(
        val deviceGuid: String?,
        val sessionId: String?,
        val enrolledLevel: String?,
        val counts: Counts,
        val environment: Map<String, Any?>,
        val motionSensors: String,
        val lastMessage: String,
        /** Sensors this phone has, by wire name (empty before the screen starts capturing). */
        val sensorsAvailable: List<String> = emptyList(),
        /** Lifetime samples and events per signal name since the device started. */
        val signals: Map<String, Long> = emptyMap(),
        /** Lifetime characters typed and corrected (counts only, never the characters). */
        val typedChars: Long = 0L,
        val correctedChars: Long = 0L,
    )

    private val worker = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "fortguard").apply { isDaemon = true } }
    private val main = Handler(Looper.getMainLooper())
    private val buffer = EventBuffer()

    @Volatile private var engine: FortGuardEngine? = null
    @Volatile private var config: Config? = null
    @Volatile private var lastMessage = "not started"
    private var env: EnvironmentChecks? = null
    private var motion: MotionCapture? = null
    private var timer: ScheduledFuture<*>? = null
    private val attached = HashMap<Activity, TouchCallback>()

    /** Forced environment flags for testing. Applied only when Config.allowDebugOverrides is true. */
    val debugOverrides: MutableMap<String, Boolean> = java.util.concurrent.ConcurrentHashMap()

    val sessionId: String? get() = engine?.sessionId

    /** Safe to call again, for example after changing the server address. */
    fun init(context: Context, config: Config, log: (String) -> Unit = {}) {
        val app = context.applicationContext
        this.config = config
        val checks = EnvironmentChecks(app).also { env = it }
        if (motion == null) motion = MotionCapture(app, buffer)
        val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        identityFields = storedIdentity(prefs)
        val guid = deviceId(app)
        timer?.cancel(false)
        // Scheduled before the engine is built, so a saved configuration that changes the interval replaces this one.
        flushEveryMs = config.flushIntervalMs
        timer = worker.scheduleWithFixedDelay({ runCatching { engine?.flush() } }, config.flushIntervalMs, config.flushIntervalMs, TimeUnit.MILLISECONDS)
        worker.execute {
            try {
                val key = AndroidKeys.loadOrCreate() // may take a moment on StrongBox phones
                val api = ApiClient(config.baseUrl)
                val attestation = config.attestationProvider
                    ?: if (config.devAttestation) DevAttestationProvider(api, config.devAttestationLevel)
                    else AttestationProvider { throw IllegalStateException("no attestation provider configured") }
                engine = FortGuardEngine(
                    api = api, appId = config.appId, deviceGuid = guid, key = key, attestation = attestation,
                    environment = { environmentSnapshot(checks) }, platform = "Android",
                    log = { m -> lastMessage = m; log(m) }, buffer = buffer,
                    ownerProof = { p -> OwnerKeys.proofFor(p) },
                    identity = { identityFields },
                    configKey = config.configPublicKey,
                    configMemory = PrefsMemory(prefs),
                )
                engine!!.consentBehavioral = buffer.enabled // consent may have been set before the engine existed
                if (prefs.contains("location_consent")) engine!!.consentLocation = prefs.getBoolean("location_consent", false)
                engine!!.consentTexts = storedConsentTexts(prefs)
                engine!!.onPolicy = { policy -> applyPolicy(policy) }
                applyPolicy(engine!!.policy)   // a configuration saved by an earlier run is already in force
                lastMessage = "ready"
                val e = engine!!.enroll()
                lastMessage = e.message
                log(e.message)
            } catch (t: Throwable) {
                lastMessage = "init failed: ${t.message}"
                log(lastMessage)
            }
        }
    }

    @Volatile private var flushEveryMs = 5_000L

    @Volatile private var ownerWindowUntilMs = 0L
    @Volatile private var motionServiceRunning = false

    /**
     * Asks the owner to confirm with a fingerprint or face. A confirmation opens a window of
     * OwnerKeys.WINDOW_S seconds, during which every batch carries a proof that only this phone's owner
     * could have made. Needs Android 11 or later and a fingerprint or face enrolled on the phone.
     */
    fun enrolOwner(activity: Activity, onResult: (Boolean, String) -> Unit) {
        if (!OwnerKeys.supported) return onResult(false, "Owner confirmation needs Android 11 or later.")
        val biometrics = activity.getSystemService(android.hardware.biometrics.BiometricManager::class.java)
        if (biometrics.canAuthenticate(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG)
            != android.hardware.biometrics.BiometricManager.BIOMETRIC_SUCCESS) {
            return onResult(false, "Set up a fingerprint or face unlock on this phone first.")
        }
        try {
            OwnerKeys.create()
        } catch (e: Exception) {
            return onResult(false, "Could not create the owner key: ${e.message}")
        }
        // Any failure here is reported to the app, never thrown into its UI thread.
        try {
            val prompt = android.hardware.biometrics.BiometricPrompt.Builder(activity)
                .setTitle("Confirm it's you")
                .setSubtitle("FortGuard learns how this phone is usually used")
                .setNegativeButton("Cancel", activity.mainExecutor, android.content.DialogInterface.OnClickListener { _, _ -> })
                .build()
            prompt.authenticate(android.os.CancellationSignal(), activity.mainExecutor,
                object : android.hardware.biometrics.BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: android.hardware.biometrics.BiometricPrompt.AuthenticationResult) {
                        ownerWindowUntilMs = System.currentTimeMillis() + OwnerKeys.WINDOW_S * 1000L
                        onResult(true, "Confirmed. Use the app normally for the next ${OwnerKeys.WINDOW_S / 60} minutes.")
                    }
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        onResult(false, errString.toString())
                    }
                })
        } catch (e: Exception) {
            onResult(false, "Owner confirmation could not start: ${e.javaClass.simpleName}")
        }
    }

    /** Seconds left in the owner window that this app session opened, 0 when closed or unknown. */
    fun ownerWindowLeftS(): Long = ((ownerWindowUntilMs - System.currentTimeMillis()) / 1000L).coerceAtLeast(0L)

    /**
     * Keeps motion checks running after the screens close, with a visible notification. Off by default.
     * Only starts when the customer has consented to behavioural capture.
     */
    fun setBackgroundMotion(context: Context, on: Boolean) {
        val app = context.applicationContext
        app.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("background_motion", on).apply()
        val intent = android.content.Intent(app, FortGuardMotionService::class.java)
        if (on && buffer.enabled) app.startForegroundService(intent) else if (!on) app.stopService(intent)
    }

    /** True once init has run in this process. The motion service uses it to stop itself after a restart. */
    fun isStarted(): Boolean = motion != null

    internal fun motionServiceChanged(running: Boolean) {
        motionServiceRunning = running
        if (running) motion?.start() else if (attached.isEmpty()) motion?.stop()
    }

    private fun environmentSnapshot(checks: EnvironmentChecks): Map<String, Any?> {
        val base = checks.snapshot()
        return if (config?.allowDebugOverrides == true && debugOverrides.isNotEmpty()) {
            LinkedHashMap(base).apply { debugOverrides.forEach { (k, v) -> if (containsKey(k)) put(k, v) } }
        } else base
    }

    /**
     * Says which customer is using this phone, so the back office can record their time in the app and show
     * their name. Both values are checked here; nothing is sent until the next batch.
     */
    fun identify(context: Context, userId: String, customerName: String) {
        val name = cleanName(customerName)
        if (!CUSTOMER_ID.matches(userId) || name.isEmpty()) return
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("identity_user", userId).putString("identity_name", name).apply()
        identityFields = mapOf("user_id" to userId, "customer_name" to name)
    }

    /**
     * Whether the customer agrees to share their approximate location. Coordinates are sent only when this is on
     * and the app has the location permission. Turning it off stops sharing from the next batch.
     */
    fun setLocationConsent(context: Context, granted: Boolean) {
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean("location_consent", granted).apply()
        engine?.consentLocation = granted
    }

    /**
     * Records which published consent wording the customer accepted, so the bank can show what was
     * agreed to and in which words. [group] is "behavioural" or "location"; [lang] and [version] come
     * from the server's GET /v1/consent-texts.
     */
    fun acceptedConsentText(context: Context, group: String, lang: String, version: Long) {
        require(group == "behavioural" || group == "location") { "group must be behavioural or location" }
        require(Regex("[a-z]{2,3}(-[A-Z]{2})?").matches(lang) && version in 1..100_000) { "bad language or version" }
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.edit().putString("consent_text_$group", "$lang|$version").apply()
        engine?.consentTexts = storedConsentTexts(prefs)
    }

    /** What the bank's signed configuration currently lets this SDK collect. */
    val policy: com.fortguard.sdk.core.CollectionPolicy? get() = engine?.policy

    private fun storedConsentTexts(prefs: android.content.SharedPreferences): Map<String, Pair<String, Long>> {
        val out = LinkedHashMap<String, Pair<String, Long>>()
        for (group in listOf("behavioural", "location")) {
            val parts = prefs.getString("consent_text_$group", null)?.split('|') ?: continue
            val version = parts.getOrNull(1)?.toLongOrNull() ?: continue
            out[group] = parts[0] to version
        }
        return out
    }

    /** Obeys a configuration whose signature the engine has already checked. */
    private fun applyPolicy(policy: com.fortguard.sdk.core.CollectionPolicy) {
        env?.bankAllowsLocation = policy.location
        if (policy.version > 0 && policy.flushIntervalMs != flushEveryMs) {
            flushEveryMs = policy.flushIntervalMs
            timer?.cancel(false)
            timer = worker.scheduleWithFixedDelay({ runCatching { engine?.flush() } }, flushEveryMs, flushEveryMs, TimeUnit.MILLISECONDS)
        }
    }

    /** Remembers the trusted configuration key and the last accepted configuration across app starts. */
    private class PrefsMemory(private val prefs: android.content.SharedPreferences) : com.fortguard.sdk.core.ConfigMemory {
        override fun get(name: String): String? = prefs.getString("remote_$name", null)
        override fun put(name: String, value: String) { prefs.edit().putString("remote_$name", value).apply() }
    }

    fun isLocationConsent(context: Context): Boolean =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("location_consent", false)

    private fun storedIdentity(prefs: android.content.SharedPreferences): Map<String, String> {
        val userId = prefs.getString("identity_user", null) ?: return emptyMap()
        val name = prefs.getString("identity_name", null)?.let { cleanName(it) } ?: return emptyMap()
        return if (CUSTOMER_ID.matches(userId) && name.isNotEmpty()) mapOf("user_id" to userId, "customer_name" to name)
        else emptyMap()
    }

    private fun cleanName(raw: String): String = raw.filter { it.code >= 32 }.trim().take(80)

    /** Start capturing on a screen. Call from onResume. */
    fun attach(activity: Activity) {
        val window = activity.window
        if (attached.containsKey(activity)) return
        val cb = TouchCallback(window.callback, buffer) { window.peekDecorView() }
        window.callback = cb
        attached[activity] = cb
        env?.onAttach(activity)
        motion?.start()
    }

    /** Stop capturing on a screen and send what is buffered. Call from onPause. */
    fun detach(activity: Activity) {
        attached.remove(activity)?.let { cb -> if (activity.window.callback === cb) activity.window.callback = cb.base }
        env?.onDetach(activity)
        if (attached.isEmpty() && !motionServiceRunning) motion?.stop()
        flush()
    }

    /** Record typing rhythm, focus and paste for one input. Never reads its text. */
    fun watch(editText: EditText, field: Field) = watchField(editText, field, buffer)

    /** User consent for behavioral capture. When false nothing behavioral is collected or sent. */
    fun setConsent(granted: Boolean) {
        buffer.enabled = granted
        engine?.consentBehavioral = granted
        if (!granted) buffer.clear()
    }

    /** Send what is buffered now, in the background. */
    fun flush(callback: ((FortGuardEngine.Outcome) -> Unit)? = null) {
        worker.execute {
            val o = engine?.flush(force = true) ?: FortGuardEngine.Outcome(false, "SDK not ready: $lastMessage")
            lastMessage = o.message
            callback?.let { cb -> main.post { cb(o) } }
        }
    }

    /** Mark the user pressing the confirm button, then send everything. Call before your backend asks for a decision. */
    fun submit(callback: (FortGuardEngine.Outcome) -> Unit) {
        buffer.ui("SUBMIT", Field.OTHER, System.currentTimeMillis())
        flush(callback)
    }

    /** Re-enroll, for example after changing the test attestation level. */
    fun reenroll(callback: (FortGuardEngine.Outcome) -> Unit) {
        worker.execute {
            val o = engine?.enroll(force = true) ?: FortGuardEngine.Outcome(false, "SDK not ready: $lastMessage")
            lastMessage = o.message
            main.post { callback(o) }
        }
    }

    fun newSession(): String? {
        val id = engine?.newSession()
        buffer.clear()
        return id
    }

    /** Forget this device: deletes the hardware key and the device ID. The next init enrolls a new device. */
    fun resetDevice(context: Context) {
        timer?.cancel(false)
        engine = null
        AndroidKeys.delete()
        OwnerKeys.delete()
        ownerWindowUntilMs = 0L
        // A reset is a tester asking for a fresh device: change the salt so the id changes too. Reinstalling
        // the app clears the salt, which brings the phone's original id back.
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.edit().remove(KEY_GUID).putInt(KEY_SALT, prefs.getInt(KEY_SALT, 0) + 1).apply()
        buffer.clear()
        lastMessage = "device reset"
    }

    fun lastBatchJson(): String? = engine?.lastBatchJson

    fun status(): Status {
        val m = motion
        val sensors = when {
            m == null -> "not started"
            !m.hasAccelerometer -> "no accelerometer"
            m.running -> "on" + if (m.hasGyroscope) "" else " (no gyroscope)"
            else -> "off (no screen attached)"
        }
        return Status(
            deviceGuid = engine?.deviceGuid, sessionId = engine?.sessionId, enrolledLevel = engine?.enrolledLevel,
            counts = buffer.counts(), environment = env?.let { environmentSnapshot(it) } ?: emptyMap(),
            motionSensors = sensors, lastMessage = lastMessage,
            sensorsAvailable = m?.available() ?: emptyList(),
            signals = buffer.signals(), typedChars = buffer.typing().first, correctedChars = buffer.typing().second,
        )
    }

    private const val PREFS = "fortguard"
    private val CUSTOMER_ID = Regex("[A-Za-z0-9_-]{1,64}")
    @Volatile private var identityFields: Map<String, String> = emptyMap()
    private const val KEY_GUID = "device_guid"
    private const val KEY_SALT = "device_salt"

    /**
     * This phone's FortGuard device id: the same value after the app is uninstalled and installed again,
     * and the one the back office shows. It can be read before init().
     *
     * It is a one-way hash of Android's per-app device identifier (ANDROID_ID), so it differs from the id
     * any other company's app sees, cannot be turned back into the Android value, and changes on a factory
     * reset or if the app is signed with a different key. Only if Android gives no identifier does the SDK
     * fall back to a random id kept in app storage, which a reinstall does lose.
     */
    fun deviceId(context: Context): String {
        val app = context.applicationContext
        val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val androidId = runCatching { Settings.Secure.getString(app.contentResolver, Settings.Secure.ANDROID_ID) }.getOrNull()
        // 9774d56d682e549c is a value some old, faulty phones all shared; it identifies nothing.
        if (!androidId.isNullOrBlank() && androidId != "9774d56d682e549c") {
            val salt = prefs.getInt(KEY_SALT, 0)
            val digest = MessageDigest.getInstance("SHA-256").digest("fortguard.device.v1|$androidId|$salt".toByteArray())
            return "dev_" + digest.joinToString("") { "%02x".format(it) }.take(24)
        }
        return prefs.getString(KEY_GUID, null) ?: Ids.random("dev_", 12).also { prefs.edit().putString(KEY_GUID, it).apply() }
    }
}
