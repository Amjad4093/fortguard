import FortGuardSDK
import SwiftUI

@main
struct FortGuardDemoApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

/// DEMO ONLY. Plays the bank's server: asks FortGuard for a decision. A real app never holds the API key
/// and never calls /v1/risk/evaluate itself; the bank's backend does, with the session ID from the SDK.
enum DemoBackend {
    struct Decision {
        let score: Int
        let level: String
        let action: String
        let breakdown: [(String, Int)]
        let bot: Double
        let coercion: Double
        let remoteTool: Bool
        let latencyMs: Double
    }

    static func evaluate(server: String, apiKey: String, sessionId: String, userId: String, amount: Double,
                         beneficiary: String, newPayee: Bool) -> Result<Decision, FortGuardError> {
        let r = ApiClient(baseURL: server).postJSON("/v1/risk/evaluate", [
            "session_id": .string(sessionId), "user_id": .string(userId), "event_type": "FUNDS_TRANSFER",
            "request_id": .string(Ids.random("req_", 12)),
            "transaction_details": .object(["amount": .double(amount), "currency": "PKR",
                                            "beneficiary_account": .string(beneficiary), "is_new_beneficiary": .bool(newPayee)]),
        ], headers: ["X-API-Key": apiKey])
        guard r.status == 200, let score = r.body["risk_score"] as? Int, let level = r.body["risk_level"] as? String else {
            return .failure(FortGuardError(r.describe()))
        }
        let threat = r.body["threat_details"] as? [String: Any] ?? [:]
        let breakdown = (r.body["score_breakdown"] as? [[String: Any]] ?? []).compactMap { item -> (String, Int)? in
            guard let reason = item["reason"] as? String else { return nil }
            return (reason, item["points"] as? Int ?? 0)
        }
        return .success(Decision(score: score, level: level, action: r.body["action_recommended"] as? String ?? "",
                                 breakdown: breakdown, bot: threat["bot_probability"] as? Double ?? 0,
                                 coercion: threat["coercion_scam_probability"] as? Double ?? 0,
                                 remoteTool: threat["rat_detected"] as? Bool ?? false,
                                 latencyMs: r.body["latency_ms"] as? Double ?? 0))
    }

    static let reasons: [String: String] = [
        "REASON_DEVICE_ROOTED_OR_JAILBROKEN": "The device appears jailbroken.",
        "REASON_EMULATOR_DETECTED": "Running in a simulator, not a real phone.",
        "REASON_HOOKING_FRAMEWORK_DETECTED": "A hooking framework (such as Frida) is present.",
        "REASON_REMOTE_ACCESS_TOOL_ACTIVE": "A remote-access tool is active.",
        "REASON_SCREEN_SHARING_ACTIVE": "The screen is being shared or recorded.",
        "REASON_LOCATION_SPOOFING_SUSPECTED": "Mock location is switched on.",
        "REASON_LOCATION_JUMP_DETECTED": "The phone was in two places too far apart, too fast.",
        "REASON_ML_BEHAVIOR_ANOMALY": "The learning model found this session unlike your usual ones.",
        "REASON_VPN_OR_PROXY": "A VPN or proxy is active.",
        "REASON_ACTIVE_CALL_DURING_PAYMENT": "A call is active during the payment.",
        "REASON_PASTE_ACTIVITY_IN_BENEFICIARY_FIELD": "The beneficiary account was pasted.",
        "REASON_COGNITIVE_HESITATION_DETECTED": "Long pauses, as when someone is being coached.",
        "REASON_NEW_BENEFICIARY": "Payment to a new beneficiary.",
        "REASON_COACHED_SCAM_PATTERN": "Call plus new payee or hesitation: a coached-scam pattern.",
        "REASON_SCRIPTED_INPUT": "Typing rhythm is too regular for a person.",
        "REASON_PERFECT_LINEAR_SWIPES": "Swipes are perfectly straight.",
        "REASON_NO_PHYSICAL_MOTION": "Touches arrive but the phone does not move at all.",
        "REASON_NO_SENSOR_DATA": "No motion-sensor data was received.",
        "REASON_NO_TELEMETRY": "No behavioral data was received.",
        "REASON_DEVICE_INTEGRITY_WEAK": "Attestation shows basic integrity only.",
        "RULE_FORCE_STEP_UP": "Raised to step-up by a hard rule.",
    ]
    static let actions: [String: String] = [
        "PROCEED": "Let it through",
        "CHALLENGE_FIDO2_OR_OTP": "Ask for a second factor",
        "TERMINATE_SESSION_AND_OPEN_CASE": "End the session and open a case",
    ]
}
