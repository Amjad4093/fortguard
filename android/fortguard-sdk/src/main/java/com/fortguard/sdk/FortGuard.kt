package com.fortguard.sdk

import android.app.Activity
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.EditText
import com.fortguard.sdk.core.ApiClient
import com.fortguard.sdk.core.AttestationProvider
import com.fortguard.sdk.core.Counts
import com.fortguard.sdk.core.DevAttestationProvider
import com.fortguard.sdk.core.EventBuffer
import com.fortguard.sdk.core.Field
import com.fortguard.sdk.core.FortGuardEngine
import com.fortguard.sdk.core.Ids
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
        val guid = prefs.getString(KEY_GUID, null) ?: Ids.random("dev_", 12).also { prefs.edit().putString(KEY_GUID, it).apply() }
        timer?.cancel(false)
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
                )
                engine!!.consentBehavioral = buffer.enabled // consent may have been set before the engine existed
                lastMessage = "ready"
                val e = engine!!.enroll()
                lastMessage = e.message
                log(e.message)
            } catch (t: Throwable) {
                lastMessage = "init failed: ${t.message}"
                log(lastMessage)
            }
        }
        timer = worker.scheduleWithFixedDelay({ runCatching { engine?.flush() } }, config.flushIntervalMs, config.flushIntervalMs, TimeUnit.MILLISECONDS)
    }

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

    /** Start capturing on a screen. Call from onResume. */
    fun attach(activity: Activity) {
        val window = activity.window
        if (attached.containsKey(activity)) return
        val cb = TouchCallback(window.callback, buffer)
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
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(KEY_GUID).apply()
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
    private const val KEY_GUID = "device_guid"
}
