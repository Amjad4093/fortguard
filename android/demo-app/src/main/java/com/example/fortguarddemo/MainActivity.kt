package com.example.fortguarddemo

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
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
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import com.fortguard.sdk.FortGuard
import com.fortguard.sdk.core.Field
import java.util.concurrent.Executors

/**
 * FortGuard demo: a single transfer screen that uses the SDK the way a bank app would, plus test
 * controls (server address, forced conditions, attestation level) that a real app would not have.
 */
class MainActivity : Activity() {

    private val io = Executors.newSingleThreadExecutor()
    private val ui = Handler(Looper.getMainLooper())
    private val prefs by lazy { getSharedPreferences("demo", Context.MODE_PRIVATE) }

    private lateinit var serverInput: EditText
    private lateinit var apiKeyInput: EditText
    private lateinit var levelSpinner: Spinner
    private lateinit var statusText: TextView
    private lateinit var accountInput: EditText
    private lateinit var amountInput: EditText
    private lateinit var newPayee: CheckBox
    private lateinit var consent: CheckBox
    private lateinit var resultText: TextView
    private lateinit var checkButton: Button

    @Volatile private var attestationLevel = "STRONG"

    private val forced = linkedMapOf(
        "active_call" to "On a call",
        "screen_sharing" to "Screen sharing",
        "active_remote_software" to "Remote-access tool",
        "is_rooted" to "Rooted",
        "vpn" to "VPN",
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildUi())
        startSdk()
        refreshStatus()
    }

    override fun onResume() {
        super.onResume()
        FortGuard.attach(this)
    }

    override fun onPause() {
        FortGuard.detach(this)
        super.onPause()
    }

    override fun onDestroy() {
        ui.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private fun startSdk() {
        val url = serverInput.text.toString().trim()
        prefs.edit().putString("server", url).putString("api_key", apiKeyInput.text.toString().trim()).apply()
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
        FortGuard.setConsent(consent.isChecked)
    }

    // --- Actions ----------------------------------------------------------------------------------

    private fun checkRisk() {
        val account = accountInput.text.toString().trim()
        val amount = amountInput.text.toString().replace(",", "").toDoubleOrNull()
        if (account.length !in 8..40) { showError("Enter a beneficiary account of 8 to 40 characters."); return }
        if (amount == null || amount <= 0) { showError("Enter an amount greater than zero."); return }
        checkButton.isEnabled = false
        resultText.text = "Sending telemetry and asking for a decision..."
        resultText.setTextColor(Color.DKGRAY)
        FortGuard.submit { outcome ->
            if (!outcome.ok) {
                checkButton.isEnabled = true
                showError("Telemetry not accepted: ${outcome.message}")
                return@submit
            }
            val session = FortGuard.sessionId ?: return@submit
            val url = serverInput.text.toString().trim()
            val key = apiKeyInput.text.toString().trim()
            io.execute {
                val result = DemoBackend.evaluate(url, key, session, userId(), amount, account, newPayee.isChecked)
                ui.post {
                    checkButton.isEnabled = true
                    result.fold(::showDecision) { showError("Evaluate failed: ${it.message}") }
                }
            }
        }
    }

    private fun showDecision(d: DemoBackend.Decision) {
        val sb = StringBuilder()
        sb.append("${d.level.replace('_', ' ')}   ${d.score} / 1000\n")
        sb.append("${DemoBackend.ACTIONS[d.action] ?: d.action}\n\n")
        if (d.breakdown.isEmpty()) sb.append("No risk signals fired.\n")
        d.breakdown.forEach { (reason, points) -> sb.append("+$points  ${DemoBackend.REASONS[reason] ?: reason}\n") }
        sb.append("\nBot ${pct(d.botProbability)}, coercion ${pct(d.coercionProbability)}, remote tool ${if (d.remoteTool) "yes" else "no"}. Scored in ${d.latencyMs} ms.")
        resultText.text = sb.toString()
        resultText.setTextColor(when (d.level) {
            "ALLOW" -> Color.rgb(29, 122, 70)
            "STEP_UP" -> Color.rgb(138, 90, 0)
            else -> Color.rgb(179, 38, 30)
        })
    }

    private fun showError(message: String) {
        resultText.text = message
        resultText.setTextColor(Color.rgb(179, 38, 30))
    }

    private fun pct(v: Double) = "${Math.round(v * 100)}%"

    private fun userId(): String =
        prefs.getString("user", null) ?: ("usr_" + java.util.UUID.randomUUID().toString().replace("-", "").take(10))
            .also { prefs.edit().putString("user", it).apply() }

    private fun refreshStatus() {
        val s = FortGuard.status()
        val env = s.environment.filterKeys { it != "os" && it != "os_version" }
            .filterValues { it == true }.keys.joinToString().ifEmpty { "nothing flagged" }
        statusText.text = buildString {
            append("Device: ${s.deviceGuid ?: "starting"}\n")
            append("Enrollment: ${s.enrolledLevel?.let { "enrolled, attestation $it (simulated)" } ?: "not yet"}\n")
            append("Session: ${s.sessionId ?: "-"}\n")
            append("Motion sensors: ${s.motionSensors}\n")
            append("Captured: ${s.counts.touch} touch, ${s.counts.keys} edits, ${s.counts.ui} UI, ${s.counts.sensor} motion\n")
            append("Device checks: $env\n")
            append("Last: ${s.lastMessage}")
        }
        ui.postDelayed(::refreshStatus, 1000)
    }

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

    // --- Layout (plain views, no extra libraries) ------------------------------------------------------

    private fun buildUi(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(32))
        }
        root.addView(heading("FortGuard demo"))
        root.addView(note("Test app for the FortGuard SDK. Attestation is simulated by a server running with --dev. Typed text never leaves the phone: only edit timing and the field name."))

        root.addView(section("Server"))
        serverInput = input(prefs.getString("server", "http://192.168.1.100:8080")!!, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
        root.addView(label("FortGuard server address")); root.addView(serverInput)
        apiKeyInput = input(prefs.getString("api_key", "dev-only-api-key")!!, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS)
        root.addView(label("API key (plays the bank's server; a real app never holds it)")); root.addView(apiKeyInput)
        levelSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, listOf("STRONG", "DEVICE", "BASIC"))
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                    attestationLevel = parent?.getItemAtPosition(position)?.toString() ?: "STRONG"
                }
                override fun onNothingSelected(parent: AdapterView<*>?) = Unit
            }
        }
        root.addView(label("Attestation level the dev server grants")); root.addView(levelSpinner)
        root.addView(row(
            button("Connect") { startSdk(); resultText.text = "" },
            button("Re-enroll") { FortGuard.reenroll { o -> resultText.text = o.message; resultText.setTextColor(Color.DKGRAY) } },
        ))

        root.addView(section("Status"))
        statusText = TextView(this).apply { textSize = 13f; setTextIsSelectable(true) }
        root.addView(statusText)
        root.addView(row(
            button("New session") { accountInput.setText(""); amountInput.setText(""); FortGuard.newSession(); resultText.text = "" },
            button("Last batch") { showLastBatch() },
            button("Reset device") { FortGuard.resetDevice(this); startSdk() },
        ))

        root.addView(section("Force conditions (testing only)"))
        root.addView(note("The SDK detects these itself. Ticking a box forces it on, to test the server's rules. It cannot hide a real detection."))
        forced.forEach { (key, text) ->
            root.addView(CheckBox(this).apply {
                this.text = text
                setOnCheckedChangeListener { _, on -> if (on) FortGuard.debugOverrides.put(key, true) else FortGuard.debugOverrides.remove(key) }
            })
        }
        consent = CheckBox(this).apply {
            text = "User consents to behavioral capture"
            isChecked = true
            setOnCheckedChangeListener { _, on -> FortGuard.setConsent(on) }
        }
        root.addView(consent)

        root.addView(section("Transfer"))
        accountInput = input("", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS).apply { hint = "PK36EXMP00992201029381" }
        root.addView(label("Beneficiary account")); root.addView(accountInput)
        amountInput = input("", InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_DECIMAL).apply { hint = "250000" }
        root.addView(label("Amount (PKR)")); root.addView(amountInput)
        newPayee = CheckBox(this).apply { text = "New beneficiary"; isChecked = true }
        root.addView(newPayee)
        FortGuard.watch(accountInput, Field.BENEFICIARY_ACCOUNT)
        FortGuard.watch(amountInput, Field.AMOUNT)
        checkButton = button("Check risk") { checkRisk() }
        root.addView(checkButton, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(12) })

        resultText = TextView(this).apply { textSize = 15f; setPadding(0, dp(16), 0, 0); setTextIsSelectable(true) }
        root.addView(resultText)

        return ScrollView(this).apply { addView(root) }
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
    private fun heading(t: String) = TextView(this).apply { text = t; textSize = 22f; setTypeface(typeface, Typeface.BOLD) }
    private fun section(t: String) = TextView(this).apply {
        text = t; textSize = 17f; setTypeface(typeface, Typeface.BOLD); setPadding(0, dp(20), 0, dp(4))
    }
    private fun label(t: String) = TextView(this).apply { text = t; textSize = 13f; setPadding(0, dp(8), 0, 0) }
    private fun note(t: String) = TextView(this).apply { text = t; textSize = 13f; setTextColor(Color.GRAY); setPadding(0, dp(4), 0, dp(4)) }
    private fun input(value: String, type: Int) = EditText(this).apply { setText(value); inputType = type; setSingleLine(true) }
    private fun button(t: String, onClick: () -> Unit) = Button(this).apply { text = t; setOnClickListener { onClick() } }
    private fun row(vararg views: View) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        views.forEach { addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)) }
    }
}
