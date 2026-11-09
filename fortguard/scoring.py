"""Rules-only scoring: features and flags in, a 0 to 1000 score, a level and reason codes out.

No machine learning in this slice. The shape of the answer matches the BRD so that models can
replace the rules behind the same contract later (backlog items E3-02 to E3-08).
"""

from . import config
from .features import compute_features

FORCE_STEP_UP_REASONS = (
    "REASON_DEVICE_ROOTED_OR_JAILBROKEN",
    "REASON_EMULATOR_DETECTED",
    "REASON_HOOKING_FRAMEWORK_DETECTED",
    "REASON_REMOTE_ACCESS_TOOL_ACTIVE",
)
BOT_REASONS = (
    "REASON_EMULATOR_DETECTED",
    "REASON_SCRIPTED_INPUT",
    "REASON_PERFECT_LINEAR_SWIPES",
    "REASON_NO_PHYSICAL_MOTION",
)
COERCION_REASONS = (
    "REASON_ACTIVE_CALL_DURING_PAYMENT",
    "REASON_COGNITIVE_HESITATION_DETECTED",
    "REASON_NEW_BENEFICIARY",
    "REASON_COACHED_SCAM_PATTERN",
)


def level_for(score, event_type):
    bands = config.bands_for(event_type)
    if score >= bands["block_from"]:
        return "BLOCK"
    if score >= bands["step_up_from"]:
        return "STEP_UP"
    return "ALLOW"


def _behavioral_reasons(feats, sensitive):
    found = []
    flights = feats["ft_keystroke_flight_count"]
    if (
        flights >= config.SCRIPTED_MIN_KEYS
        and feats["ft_keystroke_flight_time_std"] is not None
        and feats["ft_keystroke_flight_time_std"] < config.SCRIPTED_FLIGHT_STD_MS
    ):
        found.append("REASON_SCRIPTED_INPUT")
    if (
        feats["ft_swipe_count"] >= config.LINEAR_MIN_SWIPES
        and feats["ft_swipe_curvature_max_px"] <= config.LINEAR_MEAN_DEVIATION_PX
    ):
        found.append("REASON_PERFECT_LINEAR_SWIPES")

    if feats["ft_touch_count"] >= config.NO_MOTION_MIN_TOUCHES:
        if feats["ft_accel_samples"] >= 10:
            if (
                feats["ft_accel_variance"] is not None
                and feats["ft_accel_variance"] < config.NO_MOTION_ACCEL_VAR
                and (feats["ft_gyro_variance"] or 0.0) < config.NO_MOTION_GYRO_VAR
            ):
                found.append("REASON_NO_PHYSICAL_MOTION")
        else:
            found.append("REASON_NO_SENSOR_DATA")

    if sensitive:
        if feats["ft_paste_beneficiary_count"] >= 1:
            found.append("REASON_PASTE_ACTIVITY_IN_BENEFICIARY_FIELD")
        if feats["ft_hesitation_index"] >= config.HESITATION_FLAG:
            found.append("REASON_COGNITIVE_HESITATION_DETECTED")
    return found


def score_session(session, event_type, tx, baselines=None, user_id=None):
    env = session.env
    sensitive = event_type in config.SENSITIVE_EVENTS
    tx = tx or {}
    reasons = []

    if env.get("is_rooted"):
        reasons.append("REASON_DEVICE_ROOTED_OR_JAILBROKEN")
    if env.get("is_emulator"):
        reasons.append("REASON_EMULATOR_DETECTED")
    if env.get("has_hooking_framework"):
        reasons.append("REASON_HOOKING_FRAMEWORK_DETECTED")
    if env.get("active_remote_software"):
        reasons.append("REASON_REMOTE_ACCESS_TOOL_ACTIVE")
    # The flags above are reported by the app itself, so a compromised app can lie. The attestation
    # level comes from Google or Apple through the server, so it is the independent signal.
    if session.integrity == "BASIC":
        reasons.append("REASON_DEVICE_INTEGRITY_WEAK")
    if env.get("mock_location"):
        reasons.append("REASON_LOCATION_SPOOFING_SUSPECTED")
    if env.get("vpn"):
        reasons.append("REASON_VPN_OR_PROXY")
    if sensitive and env.get("screen_sharing"):
        reasons.append("REASON_SCREEN_SHARING_ACTIVE")
    if sensitive and env.get("active_call"):
        reasons.append("REASON_ACTIVE_CALL_DURING_PAYMENT")
    new_payee = bool(tx.get("is_new_beneficiary")) and sensitive
    if new_payee:
        reasons.append("REASON_NEW_BENEFICIARY")

    feats = None
    if session.consent_behavioral:
        if session.event_count() == 0:
            reasons.append("REASON_NO_TELEMETRY")
        else:
            feats = compute_features(session)
            reasons.extend(_behavioral_reasons(feats, sensitive))

    baseline = None
    if baselines is not None and user_id is not None and feats is not None:
        baseline, anomalous = baselines.assess(user_id, feats)
        if anomalous:
            reasons.append("REASON_BEHAVIORAL_ANOMALY_HIGH")

    if (
        sensitive
        and env.get("active_call")
        and (new_payee or "REASON_COGNITIVE_HESITATION_DETECTED" in reasons)
    ):
        reasons.append("REASON_COACHED_SCAM_PATTERN")

    breakdown = [{"reason": r, "points": config.WEIGHTS[r]} for r in reasons]
    score = min(config.SCORE_MAX, sum(item["points"] for item in breakdown))
    if score < config.FORCE_STEP_UP_MIN_SCORE and any(r in reasons for r in FORCE_STEP_UP_REASONS):
        breakdown.append(
            {"reason": "RULE_FORCE_STEP_UP", "points": config.FORCE_STEP_UP_MIN_SCORE - score}
        )
        score = config.FORCE_STEP_UP_MIN_SCORE
    breakdown.sort(key=lambda item: -item["points"])

    level = level_for(score, event_type)

    def share(names, full):
        return round(min(1.0, sum(config.WEIGHTS[r] for r in reasons if r in names) / full), 2)

    return {
        "risk_score": score,
        "risk_level": level,
        "action_recommended": config.ACTIONS[level],
        "reason_codes": [item["reason"] for item in breakdown if item["reason"] in config.WEIGHTS],
        "threat_details": {
            "bot_probability": share(BOT_REASONS, 500.0),
            "rat_detected": "REASON_REMOTE_ACCESS_TOOL_ACTIVE" in reasons,
            "coercion_scam_probability": share(COERCION_REASONS, 700.0),
            "user_biometric_match_score": baseline["match_score"] if baseline else None,
        },
        "baseline": baseline or {"status": "NONE", "sessions": 0, "required": config.BASELINE_MIN_SESSIONS,
                                 "match_score": None, "match_score_preview": None, "least_typical_features": []},
        "score_breakdown": breakdown,
        "signals_used": "ENVIRONMENT_AND_BEHAVIOR" if feats is not None else "ENVIRONMENT_ONLY",
        "scoring_mode": "RULES_ONLY",
        "model_version": config.MODEL_VERSION,
        "degraded": False,
        "_features": feats,
    }


DEGRADED_REASONS = ("REASON_DEGRADED_NO_TELEMETRY", "REASON_DEGRADED_SCORING_ERROR")


def degraded_decision(event_type, tx, reason):
    """Answer from the transaction alone when behavior cannot be scored (PRD fail policy).

    A new payee or a large amount steps up; everything else is allowed and logged. Never a BLOCK:
    blocking a customer because FortGuard had a problem would be worse than asking for a second factor.
    """
    assert reason in DEGRADED_REASONS
    tx = tx or {}
    sensitive = event_type in config.SENSITIVE_EVENTS
    amount = tx.get("amount") or 0
    risky = sensitive and (bool(tx.get("is_new_beneficiary")) or amount >= config.DEGRADED_STEP_UP_AMOUNT)
    score = config.bands_for(event_type)["step_up_from"] if risky else 0
    level = level_for(score, event_type)
    return {
        "risk_score": score,
        "risk_level": level,
        "action_recommended": config.ACTIONS[level],
        "reason_codes": [reason],
        "threat_details": {"bot_probability": 0.0, "rat_detected": False, "coercion_scam_probability": 0.0,
                           "user_biometric_match_score": None},
        "score_breakdown": [{"reason": reason, "points": score}],
        "baseline": {"status": "NONE", "sessions": 0, "required": config.BASELINE_MIN_SESSIONS,
                     "match_score": None, "match_score_preview": None, "least_typical_features": []},
        "signals_used": "TRANSACTION_ONLY",
        "scoring_mode": "DEGRADED",
        "model_version": config.MODEL_VERSION,
        "degraded": True,
    }
