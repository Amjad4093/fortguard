package com.example.fortguarddemo

import com.fortguard.sdk.core.ApiClient
import com.fortguard.sdk.core.Ids

/**
 * DEMO ONLY. Plays the bank's server: asks FortGuard for a decision.
 *
 * In a real app this call is made by the bank's backend with its own API key. A mobile app must never
 * hold that key or call /v1/risk/evaluate itself, because anyone can pull a key out of an APK.
 */
object DemoBackend {

    data class Decision(
        val score: Int,
        val level: String,
        val action: String,
        val breakdown: List<Pair<String, Int>>,
        val botProbability: Double,
        val coercionProbability: Double,
        val remoteTool: Boolean,
        val latencyMs: Double,
    )

    fun evaluate(
        baseUrl: String, apiKey: String, sessionId: String, userId: String,
        amount: Double, beneficiary: String, newPayee: Boolean,
    ): Result<Decision> = runCatching {
        val r = ApiClient(baseUrl).postJson(
            "/v1/risk/evaluate",
            mapOf(
                "session_id" to sessionId, "user_id" to userId, "event_type" to "FUNDS_TRANSFER",
                "request_id" to Ids.random("req_", 12),
                "transaction_details" to mapOf(
                    "amount" to amount, "currency" to "PKR",
                    "beneficiary_account" to beneficiary, "is_new_beneficiary" to newPayee,
                ),
            ),
            mapOf("X-API-Key" to apiKey),
        )
        check(r.status == 200) { r.describe() }
        val b = r.body
        val threat = b["threat_details"] as? Map<*, *> ?: emptyMap<String, Any?>()
        val breakdown = (b["score_breakdown"] as? List<*>).orEmpty().mapNotNull { item ->
            val m = item as? Map<*, *> ?: return@mapNotNull null
            (m["reason"] as? String ?: return@mapNotNull null) to ((m["points"] as? Number)?.toInt() ?: 0)
        }
        Decision(
            score = (b["risk_score"] as Number).toInt(),
            level = b["risk_level"] as String,
            action = b["action_recommended"] as String,
            breakdown = breakdown,
            botProbability = (threat["bot_probability"] as? Number)?.toDouble() ?: 0.0,
            coercionProbability = (threat["coercion_scam_probability"] as? Number)?.toDouble() ?: 0.0,
            remoteTool = threat["rat_detected"] == true,
            latencyMs = (b["latency_ms"] as? Number)?.toDouble() ?: 0.0,
        )
    }

    val REASONS = mapOf(
        "REASON_DEVICE_ROOTED_OR_JAILBROKEN" to "The device appears rooted.",
        "REASON_EMULATOR_DETECTED" to "Running in an emulator, not a real phone.",
        "REASON_HOOKING_FRAMEWORK_DETECTED" to "A hooking framework (such as Frida) is present.",
        "REASON_REMOTE_ACCESS_TOOL_ACTIVE" to "A remote-access tool is active.",
        "REASON_SCREEN_SHARING_ACTIVE" to "The screen is being shared or recorded.",
        "REASON_LOCATION_SPOOFING_SUSPECTED" to "Mock location is switched on.",
        "REASON_LOCATION_JUMP_DETECTED" to "The phone was in two places too far apart, too fast.",
        "REASON_ML_BEHAVIOR_ANOMALY" to "The learning model found this session unlike your usual ones.",
        "REASON_VPN_OR_PROXY" to "A VPN or proxy is active.",
        "REASON_ACTIVE_CALL_DURING_PAYMENT" to "A call is active during the payment.",
        "REASON_PASTE_ACTIVITY_IN_BENEFICIARY_FIELD" to "The beneficiary account was pasted.",
        "REASON_COGNITIVE_HESITATION_DETECTED" to "Long pauses, as when someone is being coached.",
        "REASON_NEW_BENEFICIARY" to "Payment to a new beneficiary.",
        "REASON_COACHED_SCAM_PATTERN" to "Call plus new payee or hesitation: a coached-scam pattern.",
        "REASON_SCRIPTED_INPUT" to "Typing rhythm is too regular for a person.",
        "REASON_PERFECT_LINEAR_SWIPES" to "Swipes are perfectly straight.",
        "REASON_NO_PHYSICAL_MOTION" to "Touches arrive but the phone does not move at all.",
        "REASON_NO_SENSOR_DATA" to "No motion-sensor data was received.",
        "REASON_NO_TELEMETRY" to "No behavioral data was received.",
        "REASON_DEVICE_INTEGRITY_WEAK" to "Attestation shows basic integrity only.",
        "RULE_FORCE_STEP_UP" to "Raised to step-up by a hard rule.",
    )

    val ACTIONS = mapOf(
        "PROCEED" to "Let it through",
        "CHALLENGE_FIDO2_OR_OTP" to "Ask for a second factor",
        "TERMINATE_SESSION_AND_OPEN_CASE" to "End the session and open a case",
    )
}
