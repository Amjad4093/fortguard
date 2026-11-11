package com.fortguard.sdk

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.pm.PackageManager
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.StatFs
import android.hardware.display.DisplayManager
import android.location.Location
import android.location.LocationManager
import android.media.AudioManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.os.SystemClock
import android.provider.Settings
import android.telephony.PhoneStateListener
import android.telephony.TelephonyCallback
import android.telephony.TelephonyManager
import android.view.WindowManager
import android.view.accessibility.AccessibilityManager
import java.io.File
import java.security.MessageDigest
import java.util.Locale
import java.util.TimeZone
import java.util.function.Consumer

/**
 * On-device checks reported in the "environment" block of every batch.
 *
 * These are best-effort signals that a determined attacker on a rooted phone can hide (Magisk,
 * Shamiko and similar). That is why the server also relies on attestation from Google, which the app
 * cannot fake. Treat every check here as "raises suspicion", never as "proves safety".
 */
internal class EnvironmentChecks(context: Context) {
    private val app = context.applicationContext
    @Volatile private var screenRecordingVisible = false
    private var recordingCallback: Consumer<Int>? = null

    // Slow checks run once and are cached.
    private val rooted: Boolean by lazy { checkRooted() }
    private val emulator: Boolean by lazy { checkEmulator() }
    private val hooking: Boolean by lazy { checkHooking() }

    // Live signals, kept current by callbacks so a decision reads the state at the moment it is made.
    @Volatile private var cellularCall = false
    @Volatile private var liveNetwork = "none"
    @Volatile private var networkChanges = 0
    private var lastNetwork: String? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var phoneListener: Any? = null
    private val prefs = app.getSharedPreferences("fortguard", Context.MODE_PRIVATE) // same file as FortGuard

    // Call detail: which way the call went and when it was answered or dialled. Never the number.
    @Volatile private var callDirection = "unknown"
    @Volatile private var callStartedAt = 0L
    private var lastCallState = -1

    // How the app has been used since it started: screens opened and times it was sent to the background.
    @Volatile private var backgroundSwitches = 0
    private val screensSeen = HashSet<String>()
    private var startedActivities = 0

    // Compared once per app start with what the previous start saw. Only a hash is stored.
    private val simChanged: Boolean? by lazy { runCatching { checkSimChanged() }.getOrNull() }
    private val keyboardChanged: Boolean? by lazy {
        runCatching {
            changedSinceLastRun("fact_keyboard", Settings.Secure.getString(app.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD))
        }.getOrNull()
    }

    init {
        startNetworkWatch()
        startCallWatch()
        startUsageWatch()
    }

    fun snapshot(): Map<String, Any?> {
        startCallWatch() // READ_PHONE_STATE may have been granted since the last batch
        val fix = lastFix()
        val out = linkedMapOf<String, Any?>(
            "os" to "Android",
            "os_version" to osVersion(),
            "is_rooted" to rooted,
            "is_emulator" to emulator,
            "has_hooking_framework" to hooking,
            "active_remote_software" to remoteAccessServiceEnabled(),
            "screen_sharing" to screenSharing(),
            "active_call" to (cellularCall || inCall()),
            "cellular_call" to cellularCall,
            "vpn" to vpnActive(),
            "mock_location" to (fix?.isFromMockProvider ?: false),
        )
        out.putAll(deviceFacts())
        out.putAll(securityFacts())
        if (cellularCall) {
            out["call_direction"] = callDirection
            val started = callStartedAt
            if (started > 0L) out["call_seconds"] = ((SystemClock.elapsedRealtime() - started) / 1000L).coerceIn(0L, 86_400L).toInt()
        }
        sharedLocation(fix)?.let { out["location"] = it }
        return out
    }

    /**
     * Facts about the phone and how the app is being used. None needs a permission. Each is best-effort
     * and left out when it cannot be read, so the server shows "not reported" and never a false "no".
     * Only two are scored by the server (debugger attached, SIM changed); the rest are context for the bank.
     */
    private fun securityFacts(): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        out["debugger_attached"] = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        runCatching {
            out["developer_options"] = Settings.Global.getInt(app.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        }
        runCatching {
            val am = app.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
            out["screen_reader"] = am.isTouchExplorationEnabled
        }
        runCatching { out["unknown_accessibility_service"] = unknownAccessibilityService() }
        runCatching { out["remote_access_installed"] = REMOTE_ACCESS_PACKAGES.any { installed(it) } }
        runCatching { out["font_scale"] = app.resources.configuration.fontScale.toDouble().coerceIn(0.2, 5.0) }
        runCatching { out["tz_offset_minutes"] = (TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 60_000).coerceIn(-900, 900) }
        runCatching {
            val patch = Build.VERSION.SECURITY_PATCH
            if (patch.matches(Regex("20\\d{2}-\\d{2}-\\d{2}"))) out["security_patch"] = patch
        }
        runCatching {
            val tm = app.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            val operator = tm.simOperator.orEmpty()   // mobile country code + network code, e.g. 41001
            if (operator.matches(Regex("\\d{5,6}"))) out["carrier"] = operator
            if (tm.simState == TelephonyManager.SIM_STATE_READY) out["roaming"] = tm.isNetworkRoaming
        }
        simChanged?.let { out["sim_changed"] = it }
        keyboardChanged?.let { out["keyboard_changed"] = it }
        out["background_switches"] = backgroundSwitches
        out["screens_visited"] = synchronized(screensSeen) { screensSeen.size }
        return out
    }

    /**
     * True for 72 hours after the SIM's operator is seen to differ from the previous app start: the
     * window in which a SIM-swap takeover is usually used. Null without a ready SIM or on the first run.
     */
    private fun checkSimChanged(): Boolean? {
        val tm = app.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        if (tm.simState != TelephonyManager.SIM_STATE_READY) return null
        val carrierId = if (Build.VERSION.SDK_INT >= 28) tm.simCarrierId else 0
        val changed = changedSinceLastRun("fact_sim", "${tm.simOperator}|$carrierId") ?: return null
        val now = System.currentTimeMillis()
        if (changed) prefs.edit().putLong("fact_sim_changed_at", now).apply()
        return now - prefs.getLong("fact_sim_changed_at", 0L) < SIM_CHANGE_WINDOW_MS
    }

    /** Whether the value differs from the one the previous app start stored. Null the first time, or when unknown. */
    private fun changedSinceLastRun(key: String, value: String?): Boolean? {
        if (value.isNullOrEmpty()) return null
        val hash = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
            .joinToString("") { "%02x".format(it) }.take(32)
        val previous = prefs.getString(key, null)
        prefs.edit().putString(key, hash).apply()
        return if (previous == null) null else previous != hash
    }

    /** An accessibility service is on that is neither a known screen reader nor a known remote-access tool. */
    private fun unknownAccessibilityService(): Boolean {
        val enabled = Settings.Secure.getString(app.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: return false
        return enabled.split(':').map { it.trim() }.filter { it.isNotEmpty() }
            .any { service -> (KNOWN_ACCESSIBILITY + REMOTE_ACCESS_PACKAGES).none { service.startsWith(it) } }
    }

    /** Only the packages named in this SDK's manifest <queries> can be seen; never the customer's app list. */
    private fun installed(pkg: String): Boolean =
        runCatching { app.packageManager.getPackageInfo(pkg, 0); true }.getOrDefault(false)

    /** Counts screens opened and trips to the background, from the app's own activity lifecycle. */
    private fun startUsageWatch() {
        val application = app as? Application ?: return
        application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
            override fun onActivityStarted(activity: Activity) { startedActivities++ }
            override fun onActivityResumed(activity: Activity) {
                synchronized(screensSeen) { screensSeen.add(activity.javaClass.name) }
            }
            override fun onActivityPaused(activity: Activity) = Unit
            override fun onActivityStopped(activity: Activity) {
                startedActivities = (startedActivities - 1).coerceAtLeast(0)
                // Rotating the screen stops and restarts the activity; that is not leaving the app.
                if (startedActivities == 0 && !activity.isChangingConfigurations) backgroundSwitches++
            }
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
            override fun onActivityDestroyed(activity: Activity) = Unit
        })
    }

    /**
     * Device facts that need no permission: battery, network type, locale, time zone, screen,
     * how long the app has been installed, and free storage. Each one is best-effort and omitted on error.
     */
    private fun deviceFacts(): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        runCatching {
            val model = android.os.Build.MODEL.orEmpty()
                .filter { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it in " _-.()/+" }.trim().take(80)
            if (model.isNotEmpty()) out["device_model"] = model
        }
        runCatching {
            val battery = app.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            val level = battery?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
            val scale = battery?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
            if (level >= 0 && scale > 0) out["battery_level"] = level * 100 / scale
            val status = battery?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
            out["charging"] = status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL
        }
        out["network_type"] = liveNetwork
        out["network_changes"] = networkChanges
        runCatching {
            val locale = Locale.getDefault()
            out["locale"] = if (locale.country.isEmpty()) locale.language else "${locale.language}-${locale.country}"
        }
        runCatching {
            val id = TimeZone.getDefault().id
            out["timezone"] = if (id.matches(Regex("[A-Za-z0-9_+\\-/]{1,64}"))) id else "unknown"
        }
        runCatching {
            val dm = app.resources.displayMetrics
            out["screen_width"] = dm.widthPixels
            out["screen_height"] = dm.heightPixels
            out["density"] = dm.density.toDouble()
        }
        runCatching {
            val installed = app.packageManager.getPackageInfo(app.packageName, 0).firstInstallTime
            out["app_install_age_days"] = ((System.currentTimeMillis() - installed) / 86_400_000L).coerceAtLeast(0L).toInt()
        }
        runCatching {
            val stat = StatFs(app.filesDir.path)
            out["free_storage_mb"] = (stat.availableBytes / (1024L * 1024L)).toInt()
        }
        return out
    }

    private fun networkType(): String {
        val cm = app.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return "none"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> "other"
        }
    }

    /**
     * Follows the default network as it changes. "cellular" means mobile data is carrying the traffic;
     * each switch between wifi and mobile data is counted for the session.
     */
    private fun startNetworkWatch() {
        if (networkCallback != null) return
        val cm = app.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) = noteNetwork()
            override fun onLost(network: Network) = noteNetwork()
        }
        runCatching { cm.registerDefaultNetworkCallback(cb) }.onSuccess { networkCallback = cb }
        noteNetwork()
    }

    private fun noteNetwork() {
        val now = runCatching { networkType() }.getOrDefault("none")
        lastNetwork?.let { if (it != now) networkChanges++ }
        lastNetwork = now
        liveNetwork = now
    }

    /**
     * Live cellular-call detection: the phone's own call state, from the telephony service. Needs
     * READ_PHONE_STATE, which the customer grants in the app. Without it, only VoIP calls are seen (audio mode).
     */
    private fun startCallWatch() {
        if (phoneListener != null) return
        if (app.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) return
        val tm = app.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        runCatching {
            if (Build.VERSION.SDK_INT >= 31) registerCallCallback(tm) else registerLegacyCallListener(tm)
        }
    }

    @SuppressLint("NewApi")
    private fun registerCallCallback(tm: TelephonyManager) {
        val cb = object : TelephonyCallback(), TelephonyCallback.CallStateListener {
            override fun onCallStateChanged(state: Int) = noteCallState(state)
        }
        tm.registerTelephonyCallback(app.mainExecutor, cb)
        phoneListener = cb
    }

    @Suppress("DEPRECATION")
    private fun registerLegacyCallListener(tm: TelephonyManager) {
        val listener = object : PhoneStateListener() {
            @Deprecated("Replaced by TelephonyCallback on Android 12 and later")
            override fun onCallStateChanged(state: Int, phoneNumber: String?) = noteCallState(state)
        }
        tm.listen(listener, PhoneStateListener.LISTEN_CALL_STATE)
        phoneListener = listener
    }

    /**
     * Ringing then answered is an incoming call; idle then off-hook is one the customer dialled. A call
     * already under way when the app starts has an unknown direction. The number is never read.
     */
    private fun noteCallState(state: Int) {
        when (state) {
            TelephonyManager.CALL_STATE_RINGING -> callDirection = "incoming"
            TelephonyManager.CALL_STATE_OFFHOOK -> {
                if (lastCallState == TelephonyManager.CALL_STATE_IDLE) callDirection = "outgoing"
                if (callStartedAt == 0L) callStartedAt = SystemClock.elapsedRealtime()
            }
            else -> {
                callDirection = "unknown"
                callStartedAt = 0L
            }
        }
        lastCallState = state
        cellularCall = state != TelephonyManager.CALL_STATE_IDLE
    }

    // --- Approximate location ---------------------------------------------------------------------------

    private fun hasLocationPermission(): Boolean =
        app.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
            app.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED

    /**
     * The most recent fix any provider holds, read without starting location updates. Returns null without
     * the location permission, or when no fix exists. The fix is read for the mock-location check either way;
     * its coordinates are sent only with the customer's consent.
     */
    @SuppressLint("MissingPermission")
    private fun lastFix(): Location? {
        if (!hasLocationPermission()) return null
        val lm = app.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        return runCatching {
            lm.getProviders(true).mapNotNull { lm.getLastKnownLocation(it) }.maxByOrNull { it.time }
        }.getOrNull()
    }

    /** Coordinates rounded to about 1 km, and only when the customer agreed and the fix is under 30 minutes old. */
    private fun sharedLocation(fix: Location?): Map<String, Any?>? {
        if (fix == null || !prefs.getBoolean("location_consent", false)) return null
        val ageS = ((System.currentTimeMillis() - fix.time) / 1000L).coerceAtLeast(0L)
        if (ageS > 1800) return null
        return linkedMapOf(
            "lat" to round2(fix.latitude),
            "lng" to round2(fix.longitude),
            "accuracy_m" to fix.accuracy.toInt().coerceIn(0, 100000),
            "fix_age_s" to ageS.toInt(),
        )
    }

    private fun round2(v: Double): Double = Math.round(v * 100.0) / 100.0

    // --- Screen recording (Android 15+) and mirroring -----------------------------------------

    fun onAttach(activity: Activity) {
        if (Build.VERSION.SDK_INT >= 35) {
            runCatching {
                val cb = Consumer<Int> { state -> screenRecordingVisible = state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE }
                val initial = activity.windowManager.addScreenRecordingCallback(activity.mainExecutor, cb)
                screenRecordingVisible = initial == WindowManager.SCREEN_RECORDING_STATE_VISIBLE
                recordingCallback = cb
            }
        }
    }

    fun onDetach(activity: Activity) {
        if (Build.VERSION.SDK_INT >= 35) {
            recordingCallback?.let { cb -> runCatching { activity.windowManager.removeScreenRecordingCallback(cb) } }
            recordingCallback = null
        }
    }

    private fun screenSharing(): Boolean {
        if (screenRecordingVisible) return true
        // Casting or mirroring to another display usually shows up as an extra presentation display.
        val dm = app.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
        return dm.getDisplays(DisplayManager.DISPLAY_CATEGORY_PRESENTATION).isNotEmpty()
    }

    // --- Calls, VPN ----------------------------------------------------------------------------------

    /** True during a phone call and during VoIP calls (WhatsApp and similar), as scammers often use. */
    private fun inCall(): Boolean {
        val am = app.getSystemService(Context.AUDIO_SERVICE) as AudioManager
        return am.mode == AudioManager.MODE_IN_CALL || am.mode == AudioManager.MODE_IN_COMMUNICATION
    }

    private fun vpnActive(): Boolean = runCatching {
        val cm = app.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        cm.getNetworkCapabilities(cm.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }.getOrDefault(false)

    // --- Remote access ---------------------------------------------------------------------------------

    /**
     * Remote-control apps need an accessibility service to tap and type on the phone. An enabled service
     * from a known remote-access app is a strong sign someone else may be driving the phone. Keep this
     * list maintained; it is not complete.
     */
    private fun remoteAccessServiceEnabled(): Boolean {
        val enabled = Settings.Secure.getString(app.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: return false
        return REMOTE_ACCESS_PACKAGES.any { enabled.contains("$it/") }
    }

    // --- Root, emulator, hooking --------------------------------------------------------------------------

    private fun checkRooted(): Boolean {
        val paths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sbin/su", "/vendor/bin/su",
            "/system/app/Superuser.apk", "/data/adb/magisk", "/system/bin/magisk",
        )
        return paths.any { runCatching { File(it).exists() }.getOrDefault(false) } ||
            (Build.TAGS?.contains("test-keys") == true)
    }

    private fun checkEmulator(): Boolean {
        val fp = Build.FINGERPRINT.lowercase()
        val model = Build.MODEL.lowercase()
        val product = Build.PRODUCT.lowercase()
        return fp.startsWith("generic") || fp.contains("emulator") || fp.contains("vbox") ||
            model.contains("emulator") || model.contains("android sdk built for") ||
            Build.HARDWARE in setOf("goldfish", "ranchu") ||
            product.contains("sdk_gphone") || product.contains("emulator") || product.contains("simulator")
    }

    private fun checkHooking(): Boolean {
        val inMaps = runCatching {
            File("/proc/self/maps").useLines { lines ->
                lines.any { l ->
                    val s = l.lowercase()
                    s.contains("frida") || s.contains("xposed") || s.contains("lsposed") || s.contains("substrate")
                }
            }
        }.getOrDefault(false)
        val xposedClass = runCatching { Class.forName("de.robv.android.xposed.XposedBridge"); true }.getOrDefault(false)
        return inMaps || xposedClass
    }

    private fun osVersion(): String =
        Build.VERSION.RELEASE.filter { it.isLetterOrDigit() || it in ".-_ " }.take(32).ifEmpty { "unknown" }

    companion object {
        val REMOTE_ACCESS_PACKAGES = listOf(
            "com.anydesk.anydeskandroid",
            "com.teamviewer.quicksupport.market",
            "com.teamviewer.host.market",
            "com.sand.airdroid",
            "com.carriez.flutter_hbb", // RustDesk
        )

        /** Screen readers and system accessibility features honest customers rely on. Not complete. */
        val KNOWN_ACCESSIBILITY = listOf(
            "com.google.android.marvin.talkback",
            "com.google.android.accessibility",
            "com.google.android.apps.accessibility",
            "com.android.talkback",
            "com.samsung.accessibility",
            "com.samsung.android.accessibility",
        )

        const val SIM_CHANGE_WINDOW_MS = 72L * 60 * 60 * 1000
    }
}
