package com.example.fortguarddemo

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import com.fortguard.sdk.FortGuard
import com.fortguard.sdk.core.Field
import java.util.concurrent.Executors

/**
 * FortGuard demo bank app. It shows how a bank app uses the SDK: a sign-in, a home screen, a transfer
 * with a live risk decision, a panel that lists every signal being captured, and a settings screen for
 * testers (server address, simulated attestation, forced conditions).
 *
 * The sign-in uses a built-in test account on purpose, so testers can reach the screens. It is not a
 * customer login. The API key is never stored in the app: testers type it in Settings.
 */
class MainActivity : Activity() {

    companion object {
        /** Test account, built into the demo only. Not a real customer login. */
        const val DEMO_USER = "demo"
        const val DEMO_PASSWORD = "FortGuard@2026"
        const val DEMO_NAME = "Demo Customer"
        const val REQ_PHONE = 2
        const val REQ_LOCATION = 3
        const val DEMO_BALANCE = "PKR 245,300.00"
        const val DEFAULT_SERVER = "https://hadier.pythonanywhere.com"

        val PRIMARY = Color.rgb(11, 61, 145)
        val NAVY = Color.rgb(8, 34, 84)
        val ACCENT = Color.rgb(0, 168, 143)
        val BG = Color.rgb(243, 246, 251)
        val CARD = Color.WHITE
        val INK = Color.rgb(27, 36, 48)
        val MUTED = Color.rgb(107, 119, 133)
        val OK = Color.rgb(29, 122, 70)
        val WARN = Color.rgb(138, 90, 0)
        val DANGER = Color.rgb(179, 38, 30)
    }

    private val io = Executors.newSingleThreadExecutor()
    private val ui = Handler(Looper.getMainLooper())
    private val prefs by lazy { getSharedPreferences("demo", Context.MODE_PRIVATE) }
    private val shell by lazy { FrameLayout(this) }

    private var loggedIn = false
    private var currentTab = "home"
    private var attestationLevel = "STRONG"
    private var sensorsShown: List<String> = emptyList()
    private val tabViews = HashMap<String, View>()
    private val tabButtons = HashMap<String, TextView>()
    private val signalValues = HashMap<String, TextView>()

    private var loginView: View? = null
    private lateinit var loginName: EditText
    private lateinit var callStatusView: TextView
    private lateinit var loginUser: EditText
    private lateinit var loginPassword: EditText
    private lateinit var loginError: TextView
    private lateinit var loadingStatus: TextView
    private lateinit var contentFrame: FrameLayout

    private lateinit var serverInput: EditText
    private lateinit var apiKeyInput: EditText
    private lateinit var consent: CheckBox
    private lateinit var ownerStatus: TextView
    private lateinit var statusText: TextView
    private lateinit var accountInput: EditText
    private lateinit var amountInput: EditText
    private lateinit var newPayee: CheckBox
    private lateinit var checkButton: Button
    private lateinit var resultCard: LinearLayout
    private lateinit var resultText: TextView
    private lateinit var homeDecision: TextView
    private lateinit var typingText: TextView
    private lateinit var signalsList: LinearLayout

    private val refresher = object : Runnable {
        override fun run() {
            refreshLive()
            ui.postDelayed(this, 1000)
        }
    }

    // --- Lifecycle ---------------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(shell)
        // Android 15 draws the app edge to edge. Keep the screens clear of the status bar and the navigation bar.
        shell.setOnApplyWindowInsetsListener { view, insets ->
            @Suppress("DEPRECATION")
            view.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop,
                insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
            insets
        }
        window.setBackgroundDrawable(android.graphics.drawable.ColorDrawable(BG))
        showSplash()
        startSdk()
        waitForEnrollment(0)
    }

    override fun onResume() {
        super.onResume()
        FortGuard.attach(this)
    }

    override fun onPause() {
        FortGuard.detach(this)
        super.onPause()
    }

    @Suppress("DEPRECATION")
    override fun onBackPressed() {
        // Back returns to Home first, and only leaves the app from Home.
        if (loggedIn && currentTab != "home") selectTab("home") else super.onBackPressed()
    }

    override fun onDestroy() {
        ui.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private fun startSdk() {
        val url = prefs.getString("server", DEFAULT_SERVER)!!.trim()
        FortGuard.init(
            this,
            FortGuard.Config(
                baseUrl = url,
                appId = packageName, // must be on the server's allowed list: com.example.mobilebank
                devAttestation = true,
                devAttestationLevel = { attestationLevel },
                allowDebugOverrides = true,
            ),
        )
        FortGuard.setConsent(prefs.getBoolean("consent", true))
    }

    // --- Loading and sign-in -------------------------------------------------------------------

    private fun showSplash() {
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(32), dp(32), dp(32), dp(32))
            background = GradientDrawable(GradientDrawable.Orientation.TL_BR, intArrayOf(NAVY, PRIMARY))
        }
        col.addView(text("FortGuard", 34f, Color.WHITE, bold = true))
        col.addView(text("Secure banking demo", 15f, Color.argb(210, 255, 255, 255)).apply { setPadding(0, dp(4), 0, dp(32)) })
        col.addView(ProgressBar(this).apply { isIndeterminate = true })
        loadingStatus = text("Starting...", 14f, Color.WHITE).apply { gravity = Gravity.CENTER; setPadding(0, dp(20), 0, 0) }
        col.addView(loadingStatus)
        shell.removeAllViews()
        shell.addView(col, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
    }

    private fun waitForEnrollment(tries: Int) {
        val s = FortGuard.status()
        if (s.enrolledLevel != null) {
            loadingStatus.text = "Secure session ready"
            ui.postDelayed({ showLogin() }, 500)
            return
        }
        if (tries >= 25) {
            loadingStatus.text = "Could not reach the server. You can still sign in and fix the address in Settings."
            ui.postDelayed({ showLogin() }, 1500)
            return
        }
        loadingStatus.text = if (s.deviceGuid == null) "Checking this phone..." else "Enrolling this phone with the server..."
        ui.postDelayed({ waitForEnrollment(tries + 1) }, 400)
    }

    private fun showLogin() {
        if (loggedIn) return showMain()
        val view = loginView ?: buildLogin().also { loginView = it }
        shell.removeAllViews()
        shell.addView(view, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
    }

    private fun buildLogin(): View {
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(40), dp(20), dp(24))
            setBackgroundColor(BG)
        }
        col.addView(text("FortGuard", 28f, PRIMARY, bold = true))
        col.addView(text("Sign in to your account", 15f, MUTED).apply { setPadding(0, dp(2), 0, dp(20)) })
        col.addView(text("Version ${BuildConfig.VERSION_NAME} · built ${BuildConfig.BUILD_DATE}", 12f, MUTED)
            .apply { setPadding(0, 0, 0, dp(12)) })

        val box = card()
        loginName = input("Full name", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS)
        loginUser = input("Username", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS)
        loginPassword = input("Password", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)
        // Pre-filled for testers. Set before FortGuard watches the fields, so the fill is not recorded as typing.
        loginName.setText(DEMO_NAME)
        loginUser.setText(DEMO_USER)
        loginPassword.setText(DEMO_PASSWORD)
        FortGuard.watch(loginUser, Field.USERNAME)
        FortGuard.watch(loginPassword, Field.PASSWORD)
        box.addView(label("Full name")); box.addView(loginName)
        box.addView(label("Username")); box.addView(loginUser)
        box.addView(label("Password")); box.addView(loginPassword)
        loginError = text("", 13f, DANGER).apply { setPadding(0, dp(8), 0, 0) }
        box.addView(loginError)
        box.addView(primaryButton("Sign in") { signIn() }, lp(top = 12))
        col.addView(box, lp(bottom = 16))

        val demo = card()
        demo.addView(text("Test account", 13f, INK, bold = true))
        demo.addView(text("Username: $DEMO_USER\nPassword: $DEMO_PASSWORD", 13f, MUTED).apply { setPadding(0, dp(4), 0, 0) })
        demo.addView(text("Built into this demo so testers can reach every screen. It is not a customer login.", 12f, MUTED).apply { setPadding(0, dp(6), 0, 0) })
        col.addView(demo)

        return ScrollView(this).apply { setBackgroundColor(BG); addView(col) }
    }

    private fun signIn() {
        val name = loginName.text.toString().trim()
        if (name.isEmpty()) {
            loginError.text = "Enter your full name."
            return
        }
        val ok = loginUser.text.toString().trim() == DEMO_USER && loginPassword.text.toString() == DEMO_PASSWORD
        if (!ok) {
            loginError.text = "Wrong username or password."
            return
        }
        // Tells FortGuard which customer is using this phone, so their time in the app and name reach the back office.
        FortGuard.identify(this, userId(), name)
        loggedIn = true
        loginPassword.setText("")
        loginError.text = ""
        showMain()
    }

    private fun signOut() {
        loggedIn = false
        currentTab = "home"
        ui.removeCallbacks(refresher)
        showLogin()
    }

    // --- Main shell with four tabs ----------------------------------------------------------------

    private fun showMain() {
        shell.removeAllViews()
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(BG) }
        contentFrame = FrameLayout(this)
        col.addView(contentFrame, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(CARD)
            elevation = dp(6).toFloat()
        }
        for ((key, label) in listOf("home" to "Home", "transfer" to "Send", "signals" to "Signals", "settings" to "Settings")) {
            val tab = TextView(this).apply {
                text = label
                textSize = 13f
                gravity = Gravity.CENTER
                setPadding(0, dp(14), 0, dp(14))
                setOnClickListener { selectTab(key) }
            }
            tabButtons[key] = tab
            bar.addView(tab, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        }
        col.addView(bar, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        shell.addView(col, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        selectTab(currentTab)
        ui.removeCallbacks(refresher)
        ui.post(refresher)
    }

    private fun selectTab(key: String) {
        currentTab = key
        val view = tabViews[key] ?: when (key) {
            "home" -> buildHome()
            "transfer" -> buildTransfer()
            "signals" -> buildSignals()
            else -> buildSettings()
        }.also { tabViews[key] = it }
        contentFrame.removeAllViews()
        contentFrame.addView(view, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        for ((k, tab) in tabButtons) {
            tab.setTextColor(if (k == key) PRIMARY else MUTED)
            tab.setTypeface(null, if (k == key) Typeface.BOLD else Typeface.NORMAL)
        }
        refreshLive()
    }

    private fun buildHome(): View {
        val col = column()
        col.addView(text("Hello, $DEMO_USER", 22f, INK, bold = true))
        col.addView(text("Your accounts", 14f, MUTED).apply { setPadding(0, 0, 0, dp(12)) })

        val balance = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(18), dp(18), dp(18))
            background = GradientDrawable(GradientDrawable.Orientation.TL_BR, intArrayOf(PRIMARY, NAVY)).apply { cornerRadius = dp(16).toFloat() }
        }
        balance.addView(text("Current account", 13f, Color.argb(220, 255, 255, 255)))
        balance.addView(text(DEMO_BALANCE, 26f, Color.WHITE, bold = true).apply { setPadding(0, dp(6), 0, dp(12)) })
        balance.addView(text("Protected by FortGuard", 12f, ACCENT, bold = true))
        col.addView(balance, lp(bottom = 16))

        val decision = card()
        decision.addView(text("Latest security check", 15f, INK, bold = true))
        homeDecision = text("No transfer checked yet. Send money to see a live decision.", 14f, MUTED).apply { setPadding(0, dp(6), 0, 0) }
        decision.addView(homeDecision)
        col.addView(decision, lp(bottom = 16))

        col.addView(row(
            primaryButton("Send money") { selectTab("transfer") },
            outlineButton("See signals") { selectTab("signals") },
        ))
        col.addView(text("Typed text never leaves this phone. Only timing and character counts are sent.", 12f, MUTED).apply { setPadding(0, dp(16), 0, 0) })
        return scroll(col)
    }

    private fun buildTransfer(): View {
        val col = column()
        col.addView(text("Send money", 22f, INK, bold = true).apply { setPadding(0, 0, 0, dp(12)) })
        val form = card()
        accountInput = input("Beneficiary account (IBAN)", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS)
        amountInput = input("Amount in PKR", InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_DECIMAL)
        FortGuard.watch(accountInput, Field.BENEFICIARY_ACCOUNT)
        FortGuard.watch(amountInput, Field.AMOUNT)
        form.addView(label("Beneficiary account")); form.addView(accountInput)
        form.addView(label("Amount (PKR)")); form.addView(amountInput)
        newPayee = CheckBox(this).apply { text = "New beneficiary"; isChecked = true; setTextColor(INK) }
        form.addView(newPayee, lp(top = 8))
        checkButton = primaryButton("Check risk and send") { checkRisk() }
        form.addView(checkButton, lp(top = 12))
        col.addView(form, lp(bottom = 16))

        resultCard = card()
        resultText = text("Enter the details and press the button. FortGuard decides before the money moves.", 14f, MUTED)
        resultCard.addView(resultText)
        col.addView(resultCard)
        return scroll(col)
    }

    private fun buildSignals(): View {
        val col = column()
        col.addView(text("What FortGuard sees", 22f, INK, bold = true))
        col.addView(text("Every signal this phone can provide. Values update every second while you use the app.", 13f, MUTED).apply { setPadding(0, dp(2), 0, dp(12)) })
        val typing = card()
        typingText = text("", 14f, INK)
        typing.addView(typingText)
        col.addView(typing, lp(bottom = 12))
        signalsList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(signalsList)
        return scroll(col)
    }

    private fun ownerLine(): String {
        val left = FortGuard.ownerWindowLeftS()
        return if (left > 0) "Owner confirmed. Window open for ${left / 60} min ${left % 60} s."
        else "Not confirmed. Batches are sent without owner proof."
    }

    private fun buildSettings(): View {
        val col = column()
        col.addView(text("Settings", 22f, INK, bold = true).apply { setPadding(0, 0, 0, dp(12)) })

        val server = card()
        server.addView(text("Test server", 15f, INK, bold = true))
        serverInput = input("https://your-server", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
        serverInput.setText(prefs.getString("server", DEFAULT_SERVER))
        apiKeyInput = input("API key from the server", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS)
        apiKeyInput.setText(prefs.getString("api_key", ""))
        server.addView(label("Server address")); server.addView(serverInput)
        server.addView(label("API key (your bank's server key, typed here, never stored in the app)")); server.addView(apiKeyInput)
        val levels = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, listOf("STRONG", "DEVICE", "BASIC"))
        val spinner = Spinner(this).apply {
            adapter = levels
            setSelection(levels.getPosition(attestationLevel))
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                    attestationLevel = parent?.getItemAtPosition(position)?.toString() ?: "STRONG"
                }
                override fun onNothingSelected(parent: AdapterView<*>?) = Unit
            }
        }
        server.addView(label("Attestation level (simulated by a dev server)")); server.addView(spinner)
        consent = CheckBox(this).apply {
            text = "Customer consents to behavioural capture"
            isChecked = prefs.getBoolean("consent", true)
            setTextColor(INK)
            setOnCheckedChangeListener { _, on -> prefs.edit().putBoolean("consent", on).apply(); FortGuard.setConsent(on) }
        }
        server.addView(consent, lp(top = 8))
        server.addView(row(
            primaryButton("Save and connect") {
                prefs.edit().putString("server", serverInput.text.toString().trim())
                    .putString("api_key", apiKeyInput.text.toString().trim()).apply()
                startSdk()
                toast("Saved. Connected to ${serverInput.text.toString().trim()}")
            },
            outlineButton("Re-enroll") { FortGuard.reenroll { o -> toast(o.message) } },
        ), lp(top = 12))
        col.addView(server, lp(bottom = 12))

        val device = card()
        device.addView(text("Device", 15f, INK, bold = true))
        statusText = text("", 13f, INK).apply { setPadding(0, dp(6), 0, 0); setTextIsSelectable(true) }
        device.addView(statusText)
        device.addView(row(
            outlineButton("New session") { FortGuard.newSession(); toast("New session started") },
            outlineButton("Last batch") { showLastBatch() },
        ), lp(top = 10))
        device.addView(row(
            outlineButton("Reset device") { FortGuard.resetDevice(this@MainActivity); startSdk(); toast("Device reset") },
        ), lp(top = 6))
        col.addView(device, lp(bottom = 12))

        val owner = card()
        owner.addView(text("Owner of this phone", 15f, INK, bold = true))
        owner.addView(text("Confirm with your fingerprint or face. For the next 10 minutes, batches carry proof that you confirmed, and FortGuard learns how you use the app. The app never sees your fingerprint.", 12f, MUTED))
        ownerStatus = text(ownerLine(), 13f, INK).apply { setPadding(0, dp(8), 0, 0) }
        owner.addView(ownerStatus)
        owner.addView(primaryButton("Confirm I am the owner") {
            FortGuard.enrolOwner(this@MainActivity) { ok, message ->
                toast(message)
                ownerStatus.text = ownerLine()
            }
        }, lp(top = 10))
        owner.addView(CheckBox(this).apply {
            text = "Keep motion checks running after I close the app"
            isChecked = prefs.getBoolean("background_motion", false)
            setTextColor(INK)
            setOnCheckedChangeListener { _, on ->
                if (on && android.os.Build.VERSION.SDK_INT >= 33) {
                    requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 1)
                }
                prefs.edit().putBoolean("background_motion", on).apply()
                FortGuard.setBackgroundMotion(this@MainActivity, on)
            }
        }, lp(top = 12))
        owner.addView(text("A notification shows while this is on. Touch and typing are still captured only inside the app.", 12f, MUTED).apply { setPadding(0, dp(4), 0, 0) })
        col.addView(owner, lp(bottom = 12))

        val signals = card()
        signals.addView(text("Calls and location", 15f, INK, bold = true))
        signals.addView(text("FortGuard checks whether a phone call is in progress, and whether mobile data or Wi-Fi carries your traffic. Your approximate location is shared only when you turn it on, and it is rounded to about 1 km.", 12f, MUTED))
        callStatusView = text(callLine(), 13f, INK).apply { setPadding(0, dp(8), 0, 0) }
        signals.addView(callStatusView)
        signals.addView(primaryButton("Allow call detection") {
            requestPermissions(arrayOf(android.Manifest.permission.READ_PHONE_STATE), REQ_PHONE)
        }, lp(top = 10))
        signals.addView(CheckBox(this).apply {
            text = "Share my approximate location"
            isChecked = FortGuard.isLocationConsent(this@MainActivity)
            setTextColor(INK)
            setOnCheckedChangeListener { _, on ->
                FortGuard.setLocationConsent(this@MainActivity, on)
                if (on && !locationGranted()) {
                    requestPermissions(arrayOf(android.Manifest.permission.ACCESS_COARSE_LOCATION), REQ_LOCATION)
                }
                callStatusView.text = callLine()
            }
        }, lp(top = 12))
        col.addView(signals, lp(bottom = 12))

        val forced = card()
        forced.addView(text("Conditions (testing)", 15f, INK, bold = true))
        forced.addView(text("Auto lets the SDK decide from the phone. On or Off forces the server to see that value, to test its rules.", 12f, MUTED))
        val modes = listOf("Auto", "On", "Off")
        listOf(
            "active_call" to "On a call",
            "screen_sharing" to "Screen sharing",
            "active_remote_software" to "Remote-access tool",
            "is_rooted" to "Rooted",
            "vpn" to "VPN",
        ).forEach { (key, caption) ->
            val detected = FortGuard.status().environment[key]
            val reading = when (detected) { true -> "detected yes"; false -> "detected no"; else -> "not read yet" }
            forced.addView(text("$caption  ·  $reading", 13f, INK), lp(top = 10))
            forced.addView(Spinner(this).apply {
                adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, modes)
                setSelection(when (FortGuard.debugOverrides[key]) { true -> 1; false -> 2; else -> 0 })
                onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                    override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                        when (position) {
                            1 -> FortGuard.debugOverrides[key] = true
                            2 -> FortGuard.debugOverrides[key] = false
                            else -> FortGuard.debugOverrides.remove(key)
                        }
                    }
                    override fun onNothingSelected(parent: AdapterView<*>?) = Unit
                }
            })
        }
        col.addView(forced, lp(bottom = 12))

        col.addView(outlineButton("Sign out") { signOut() })
        return scroll(col)
    }

    // --- Live updates ---------------------------------------------------------------------------

    private fun refreshLive() {
        val s = FortGuard.status()
        if (::statusText.isInitialized) {
            statusText.text = buildString {
                append("Device: ${s.deviceGuid ?: "starting"}\n")
                append("Enrollment: ${s.enrolledLevel?.let { "enrolled, attestation $it (simulated)" } ?: "not yet"}\n")
                append("Session: ${s.sessionId ?: "-"}\n")
                append("Motion sensors: ${s.motionSensors}\n")
                append("Last: ${s.lastMessage}")
            }
        }
        if (currentTab == "signals" && ::signalsList.isInitialized) renderSignals(s)
    }

    private fun renderSignals(s: FortGuard.Status) {
        if (::typingText.isInitialized) {
            typingText.text = "Characters typed: ${s.typedChars}   Corrected: ${s.correctedChars}\n" +
                "Counts only. The characters themselves are never read or sent."
        }
        if (s.sensorsAvailable != sensorsShown) {
            sensorsShown = s.sensorsAvailable
            signalsList.removeAllViews()
            signalValues.clear()
            signalGroups().forEach { (title, items) ->
                signalsList.addView(text(title, 16f, INK, bold = true).apply { setPadding(0, dp(12), 0, dp(6)) })
                val box = card()
                items.forEachIndexed { i, (name, desc) ->
                    if (i > 0) box.addView(divider())
                    box.addView(signalRow(name, desc))
                }
                signalsList.addView(box)
            }
        }
        for ((name, value) in signalValues) {
            val (msg, active) = valueFor(name, s)
            value.text = msg
            value.setTextColor(if (active) OK else MUTED)
        }
    }

    private fun signalGroups(): List<Pair<String, List<Pair<String, String>>>> = listOf(
        "Touch and gestures" to listOf("touch" to "Touch points with position, pressure and contact size"),
        "Typing" to listOf(
            "keystrokes" to "Keystroke timing per field, with typed and corrected counts",
            "ui_events" to "Focus, paste and submit events (field names only)",
        ),
        "Motion sensors" to listOf(
            "accelerometer" to "Acceleration on three axes",
            "gyroscope" to "Rotation rate",
            "magnetometer" to "Compass heading and magnetic field",
            "gravity" to "Direction of gravity, how the phone is held",
            "linear_acceleration" to "Movement without gravity",
            "rotation_vector" to "Device orientation",
            "light" to "Ambient light",
            "proximity" to "Phone near the face or ear",
            "pressure" to "Air pressure (barometer)",
        ),
        "Device facts" to listOf(
            "battery_level" to "Battery level (%)",
            "charging" to "Charging",
            "network_type" to "Network: Wi-Fi, mobile or none",
            "locale" to "Language and region",
            "timezone" to "Time zone",
            "screen_width" to "Screen width (pixels)",
            "screen_height" to "Screen height (pixels)",
            "density" to "Screen density",
            "app_install_age_days" to "Days since the app was installed",
            "free_storage_mb" to "Free storage (MB)",
        ),
        "Environment checks" to listOf(
            "is_rooted" to "Rooted device",
            "is_emulator" to "Emulator",
            "has_hooking_framework" to "Hooking framework",
            "active_remote_software" to "Remote-access app running",
            "screen_sharing" to "Screen being shared",
            "active_call" to "Phone call in progress",
            "vpn" to "VPN active",
        ),
    )

    /** The value to show for one signal, and whether it is active right now. */
    private fun valueFor(name: String, s: FortGuard.Status): Pair<String, Boolean> {
        s.signals[name]?.let { n -> if (n > 0) return "$n captured" to true }
        if (name in s.sensorsAvailable) {
            // These report only when the reading changes, so silence is normal until the phone moves or the light changes.
            if (name in listOf("light", "proximity", "pressure")) return "on this phone, reports when it changes" to false
            return "ready, waiting for data" to false
        }
        if (name in listOf("accelerometer", "gyroscope", "magnetometer", "gravity", "linear_acceleration",
                "rotation_vector", "light", "proximity", "pressure")) return "not on this phone" to false
        if (name in listOf("touch", "keystrokes", "ui_events")) return "waiting for input" to false
        val v = s.environment[name] ?: return "not reported yet" to false
        return when (v) {
            is Boolean -> when (name) {
                "charging", "is_emulator" -> (if (v) "yes" else "no") to v
                else -> (if (v) "detected" else "clear") to !v
            }
            is Number -> when (name) {
                "battery_level" -> "$v%" to true
                "free_storage_mb" -> "$v MB" to true
                "app_install_age_days" -> "$v days" to true
                else -> v.toString() to true
            }
            else -> v.toString() to true
        }
    }

    private fun signalRow(name: String, desc: String): LinearLayout {
        val item = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(8), 0, dp(8))
        }
        val left = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        left.addView(text(name.replace('_', ' '), 14f, INK, bold = true))
        left.addView(text(desc, 12f, MUTED))
        item.addView(left, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        val value = text("...", 13f, MUTED).apply { gravity = Gravity.END }
        item.addView(value)
        signalValues[name] = value
        return item
    }

    // --- Transfer --------------------------------------------------------------------------------

    private fun checkRisk() {
        val account = accountInput.text.toString().trim()
        val amount = amountInput.text.toString().replace(",", "").toDoubleOrNull()
        if (account.length !in 8..40) { showError("Enter a beneficiary account of 8 to 40 characters."); return }
        if (amount == null || amount <= 0) { showError("Enter an amount greater than zero."); return }
        checkButton.isEnabled = false
        showNeutral("Sending telemetry and asking FortGuard for a decision...")
        FortGuard.submit { outcome ->
            if (!outcome.ok) {
                checkButton.isEnabled = true
                showError("Telemetry not accepted: ${outcome.message}")
                return@submit
            }
            val session = FortGuard.sessionId ?: return@submit
            val url = prefs.getString("server", DEFAULT_SERVER)!!.trim()
            val key = prefs.getString("api_key", "")!!.trim()
            val userId = userId()
            io.execute {
                val result = DemoBackend.evaluate(url, key, session, userId, amount, account, newPayee.isChecked)
                ui.post {
                    checkButton.isEnabled = true
                    result.fold(::showDecision) { showError("Evaluate failed: ${it.message}") }
                }
            }
        }
    }

    private fun showDecision(d: DemoBackend.Decision) {
        val level = d.level
        val tone = levelColor(level)
        val sb = StringBuilder()
        sb.append("${level.replace('_', ' ')}   ${d.score} / 1000\n")
        sb.append("${DemoBackend.ACTIONS[d.action] ?: d.action}\n\n")
        if (d.breakdown.isEmpty()) sb.append("No risk signals fired.\n")
        d.breakdown.forEach { (reason, points) -> sb.append("+$points  ${DemoBackend.REASONS[reason] ?: reason}\n") }
        sb.append("\nBot ${pct(d.botProbability)}, coercion ${pct(d.coercionProbability)}, remote tool ${if (d.remoteTool) "yes" else "no"}. Scored in ${d.latencyMs} ms.")
        resultText.text = sb.toString()
        resultText.setTextColor(tone)
        resultCard.background = rounded(tint(tone), 14)
        if (::homeDecision.isInitialized) {
            homeDecision.text = "${level.replace('_', ' ')} (score ${d.score}). ${DemoBackend.ACTIONS[d.action] ?: d.action}"
            homeDecision.setTextColor(tone)
        }
    }

    private fun showError(message: String) = showNeutral(message, DANGER)

    private fun showNeutral(message: String, color: Int = MUTED) {
        resultText.text = message
        resultText.setTextColor(color)
        resultCard.background = rounded(CARD, 14)
    }

    private fun levelColor(level: String) = when (level) {
        "ALLOW" -> OK
        "STEP_UP" -> WARN
        else -> DANGER
    }

    private fun tint(c: Int): Int = Color.argb(28, Color.red(c), Color.green(c), Color.blue(c))

    private fun pct(v: Double) = "${Math.round(v * 100)}%"

    private fun locationGranted(): Boolean =
        checkSelfPermission(android.Manifest.permission.ACCESS_COARSE_LOCATION) == android.content.pm.PackageManager.PERMISSION_GRANTED

    private fun callLine(): String {
        val phone = checkSelfPermission(android.Manifest.permission.READ_PHONE_STATE) == android.content.pm.PackageManager.PERMISSION_GRANTED
        return "Call detection: " + (if (phone) "on" else "off, VoIP calls only") +
            " · Location: " + (if (FortGuard.isLocationConsent(this)) "shared" else "not shared")
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (::callStatusView.isInitialized) callStatusView.text = callLine()
    }

    private fun userId(): String =
        prefs.getString("user", null) ?: ("usr_" + java.util.UUID.randomUUID().toString().replace("-", "").take(10))
            .also { prefs.edit().putString("user", it).apply() }

    private fun showLastBatch() {
        val json = FortGuard.lastBatchJson() ?: "Nothing sent yet."
        val pretty = if (json.length > 6000) json.take(6000) + "\n... (${json.length} characters)" else json
        val tv = TextView(this).apply {
            text = pretty
            typeface = Typeface.MONOSPACE
            textSize = 11f
            setPadding(dp(16), dp(8), dp(16), dp(8))
            setTextIsSelectable(true)
        }
        AlertDialog.Builder(this)
            .setTitle("Last batch sent (no typed characters)")
            .setView(ScrollView(this).apply { addView(tv) })
            .setPositiveButton("Close", null)
            .show()
    }

    // --- Small view helpers (plain views, no extra libraries) ------------------------------------

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun rounded(color: Int, radiusDp: Int, stroke: Int? = null): GradientDrawable = GradientDrawable().apply {
        setColor(color)
        cornerRadius = dp(radiusDp).toFloat()
        if (stroke != null) setStroke(dp(1), stroke)
    }

    private fun text(t: String, size: Float, color: Int, bold: Boolean = false) = TextView(this).apply {
        this.text = t
        textSize = size
        setTextColor(color)
        if (bold) setTypeface(typeface, Typeface.BOLD)
    }

    private fun label(t: String) = TextView(this).apply {
        text = t
        textSize = 13f
        setTextColor(MUTED)
        setPadding(0, dp(10), 0, dp(2))
    }

    private fun card() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = rounded(CARD, 14)
        setPadding(dp(16), dp(16), dp(16), dp(16))
        elevation = dp(2).toFloat()
    }

    private fun column() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(16), dp(16), dp(24))
    }

    private fun scroll(child: View): View = ScrollView(this).apply {
        setBackgroundColor(BG)
        addView(child)
    }

    private fun input(hint: String, type: Int) = EditText(this).apply {
        this.hint = hint
        inputType = type
        setSingleLine(true)
        setTextColor(INK)
        setHintTextColor(Color.rgb(160, 168, 178))
        background = rounded(Color.rgb(248, 250, 253), 10, Color.rgb(200, 208, 220))
        setPadding(dp(12), dp(10), dp(12), dp(10))
    }

    private fun primaryButton(t: String, onClick: () -> Unit) = Button(this).apply {
        text = t
        isAllCaps = false
        setTextColor(Color.WHITE)
        background = rounded(PRIMARY, 12)
        setOnClickListener { onClick() }
    }

    private fun outlineButton(t: String, onClick: () -> Unit) = Button(this).apply {
        text = t
        isAllCaps = false
        setTextColor(PRIMARY)
        background = rounded(CARD, 12, PRIMARY)
        setOnClickListener { onClick() }
    }

    private fun row(vararg views: View) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        views.forEachIndexed { i, v ->
            addView(v, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { if (i > 0) leftMargin = dp(8) })
        }
    }

    private fun divider() = View(this).apply {
        setBackgroundColor(Color.rgb(230, 234, 240))
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, dp(1))
    }

    private fun lp(top: Int = 0, bottom: Int = 0) = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
        topMargin = dp(top)
        bottomMargin = dp(bottom)
    }

    private fun toast(message: String) {
        android.widget.Toast.makeText(this, message, android.widget.Toast.LENGTH_SHORT).show()
    }
}
