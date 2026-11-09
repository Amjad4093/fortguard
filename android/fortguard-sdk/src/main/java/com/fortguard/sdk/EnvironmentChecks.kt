package com.fortguard.sdk

import android.app.Activity
import android.content.Context
import android.hardware.display.DisplayManager
import android.media.AudioManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import android.view.WindowManager
import java.io.File
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

    fun snapshot(): Map<String, Any?> = linkedMapOf(
        "os" to "Android",
        "os_version" to osVersion(),
        "is_rooted" to rooted,
        "is_emulator" to emulator,
        "has_hooking_framework" to hooking,
        "active_remote_software" to remoteAccessServiceEnabled(),
        "screen_sharing" to screenSharing(),
        "active_call" to inCall(),
        "vpn" to vpnActive(),
        "mock_location" to false, // needs location access; not collected in this version
    )

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
    }
}
