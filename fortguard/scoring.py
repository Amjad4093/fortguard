"""Scoring: features and flags in, a 0 to 1000 score, a level and reason codes out.

Most of the score comes from fixed, readable rules. Two per-customer checks add to it once a customer
has enough learned sessions: the statistical baseline (baseline.py) and the machine-learning anomaly
model (mlmodel.py). Both only ever add a named reason with a fixed weight, so every decision can still
be explained line by line.
"""

from . import config, customrules, mlmodel, velocity as velocity_rules
from .features import compute_features

FORCE_STEP_UP_REASONS = (
    "REASON_DEVICE_ROOTED_OR_JAILBROKEN",
    "REASON_EMULATOR_DETECTED",
    "REASON_HOOKING_FRAMEWORK_DETECTED",
    "REASON_DEBUGGER_ATTACHED",
    "REASON_NOT_ACCOUNT_HOLDER",
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


def identity_verdict(baseline, ml, feats):
    """One plain answer to "is this the account holder?", from the customer's profile and the ML model.

    It is a judgement from behaviour, never proof: OWNER_LIKELY means this session looks like the
    sessions the profile was learned from, and NOT_OWNER_LIKELY means it does not. While the profile is
    still learning nobody can be told apart, and the answer says so instead of guessing.
    """
    required = config.BASELINE_MIN_SESSIONS
    if feats is None:
        return {"verdict": "UNKNOWN", "sessions": 0, "required": required, "match_score": None,
                "text": "No behaviour was measured in this session, so FortGuard cannot say who is using the app."}
    status = (baseline or {}).get("status", "NONE")
    sessions = (baseline or {}).get("sessions", 0)
    match = (baseline or {}).get("match_score")
    if status != "MATURE":
        left = max(0, required - sessions)
        return {"verdict": "LEARNING", "sessions": sessions, "required": required, "match_score": None,
                "text": f"Still learning this customer: {sessions} of {required} sessions. FortGuard cannot tell the "
                        f"account holder from anyone else until {left} more allowed session{'s' if left != 1 else ''}."}
    unlike = (match is not None and match < config.BASELINE_ANOMALY_BELOW) or bool((ml or {}).get("anomalous"))
    if unlike:
        return {"verdict": "NOT_OWNER_LIKELY", "sessions": sessions, "required": required, "match_score": match,
                "text": "This session does not look like the account holder. The typing, touch or movement is unlike "
                        f"the {sessions} sessions this customer's profile was learned from."}
    return {"verdict": "OWNER_LIKELY", "sessions": sessions, "required": required, "match_score": match,
            "text": f"This session looks like the account holder. It matches the profile learned from {sessions} sessions."}


def level_for(score, event_type):
    bands = config.bands_for(event_type)
    if score >= bands["block_from"]:
        return "BLOCK"
    if score >= bands["step_up_from"]:
        return "STEP_UP"
    return "ALLOW"


def _behavioral_reasons(feats, payment):
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

    if payment:
        if feats["ft_paste_beneficiary_count"] >= 1:
            found.append("REASON_PASTE_ACTIVITY_IN_BENEFICIARY_FIELD")
        if feats["ft_hesitation_index"] >= config.HESITATION_FLAG:
            found.append("REASON_COGNITIVE_HESITATION_DETECTED")
    return found


def score_session(session, event_type, tx, baselines=None, user_id=None, denied=(), velocity=None,
                  lists=(), custom=None):
    """Score one request.

    denied    deny-list kinds that matched (customer, device, account, ip)
    velocity  the counters from velocity.Velocity.snapshot, or None when history is not available
    lists     other lists the payee account is on: "mule", "allow"
    custom    customrules.CustomRules, or None
    """
    env = session.env
    payment = event_type in config.PAYMENT_EVENTS
    sensitive = event_type in config.SENSITIVE_EVENTS
    tx = tx or {}
    lists = set(lists or ())
    reasons = []
    if denied:
        reasons.append("REASON_ON_DENY_LIST")
    if payment and "mule" in lists:
        reasons.append("REASON_SUSPECTED_MULE_ACCOUNT")

    if env.get("is_rooted"):
        reasons.append("REASON_DEVICE_ROOTED_OR_JAILBROKEN")
    if env.get("is_emulator"):
        reasons.append("REASON_EMULATOR_DETECTED")
    if env.get("has_hooking_framework"):
        reasons.append("REASON_HOOKING_FRAMEWORK_DETECTED")
    if env.get("debugger_attached"):
        reasons.append("REASON_DEBUGGER_ATTACHED")
    # A remote-access tool merely being installed (env remote_access_installed) is a recorded fact and
    # never a reason: plenty of honest customers have one. Only a tool in control of the screen counts.
    if env.get("active_remote_software"):
        reasons.append("REASON_REMOTE_ACCESS_TOOL_ACTIVE")
    # The flags above are reported by the app itself, so a compromised app can lie. The attestation
    # level comes from Google or Apple through the server, so it is the independent signal.
    if session.integrity == "BASIC":
        reasons.append("REASON_DEVICE_INTEGRITY_WEAK")
    if env.get("mock_location"):
        reasons.append("REASON_LOCATION_SPOOFING_SUSPECTED")
    if session.location_jump:
        reasons.append("REASON_LOCATION_JUMP_DETECTED")
    if env.get("vpn"):
        reasons.append("REASON_VPN_OR_PROXY")
    if sensitive and env.get("screen_sharing"):
        reasons.append("REASON_SCREEN_SHARING_ACTIVE")
    in_call = bool(env.get("active_call") or env.get("cellular_call"))
    if sensitive and in_call:
        reasons.append("REASON_ACTIVE_CALL_DURING_PAYMENT")
    # A payee on the bank's allow list (its own accounts, known billers) is never treated as a new payee.
    new_payee = bool(tx.get("is_new_beneficiary")) and payment and "allow" not in lists
    if new_payee:
        reasons.append("REASON_NEW_BENEFICIARY")
    if env.get("sim_changed"):
        reasons.append("REASON_SIM_CHANGED")
        if new_payee:
            reasons.append("REASON_SIM_SWAP_PATTERN")
    if velocity is not None:
        reasons.extend(velocity_rules.reasons(velocity, payment, new_payee))

    feats = None
    if session.consent_behavioral:
        if session.event_count() == 0:
            reasons.append("REASON_NO_TELEMETRY")
        else:
            feats = compute_features(session)
            reasons.extend(_behavioral_reasons(feats, payment))

    baseline, ml = None, None
    if baselines is not None and user_id is not None and feats is not None:
        baseline, anomalous = baselines.assess(user_id, feats)
        if anomalous:
            reasons.append("REASON_BEHAVIORAL_ANOMALY_HIGH")
        ml = baselines.assess_ml(user_id, feats)
        if ml["anomalous"]:
            reasons.append("REASON_ML_BEHAVIOR_ANOMALY")
        if sensitive and ("REASON_BEHAVIORAL_ANOMALY_HIGH" in reasons or ml["anomalous"]):
            reasons.append("REASON_NOT_ACCOUNT_HOLDER")

    if (
        sensitive
        and in_call
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

    # The bank's own rules run last, on the facts and the score the built-in rules produced.
    bands = config.bands_for(event_type)
    facts = rule_facts(session, event_type, tx, feats, velocity, lists, baseline, ml, in_call, score)
    shadow_hits = []
    if custom is not None:
        live, shadow = custom.hits(facts, event_type)
        for rule in live:
            after = customrules.apply_rule(score, rule, bands)
            breakdown.append({"reason": customrules.code_for(rule["name"]), "points": after - score, "custom": True})
            score = after
        for rule in shadow:
            would = customrules.apply_rule(score, rule, bands)
            shadow_hits.append({"rule": rule["name"], "would_score": would, "would_level": level_for(would, event_type)})
    breakdown.sort(key=lambda item: -item["points"])

    level = level_for(score, event_type)

    def share(names, full):
        return round(min(1.0, sum(config.WEIGHTS[r] for r in reasons if r in names) / full), 2)

    return {
        "risk_score": score,
        "risk_level": level,
        "action_recommended": config.ACTIONS[level],
        "reason_codes": [item["reason"] for item in breakdown if item["reason"] in config.WEIGHTS or item.get("custom")],
        "threat_details": {
            "bot_probability": share(BOT_REASONS, 500.0),
            "rat_detected": "REASON_REMOTE_ACCESS_TOOL_ACTIVE" in reasons,
            "coercion_scam_probability": share(COERCION_REASONS, 700.0),
            "user_biometric_match_score": baseline["match_score"] if baseline else None,
        },
        "baseline": baseline or {"status": "NONE", "sessions": 0, "required": config.BASELINE_MIN_SESSIONS,
                                 "match_score": None, "match_score_preview": None, "least_typical_features": []},
        "ml": ml or mlmodel.EMPTY,
        "identity": identity_verdict(baseline, ml, feats),
        "score_breakdown": breakdown,
        "signals_used": "ENVIRONMENT_AND_BEHAVIOR" if feats is not None else "ENVIRONMENT_ONLY",
        # RULES_AND_ML only when the model was mature enough to give an opinion on this session.
        "scoring_mode": "RULES_AND_ML" if ml and ml["status"] == "ACTIVE" else "RULES_ONLY",
        "model_version": config.MODEL_VERSION,
        "degraded": False,
        "deny_list": sorted(denied),
        "payee_lists": sorted(lists),
        "velocity": velocity,
        "shadow_rules": shadow_hits,
        "_features": feats,
        "_rule_facts": facts,
    }


def rule_facts(session, event_type, tx, feats, velocity, lists, baseline, ml, in_call, score):
    """The facts a custom rule can read (rulelang.VARIABLES), as one flat dict. None means "no value"."""
    env = session.env
    feats = feats or {}
    v = velocity or {}

    def flag(name):
        return bool(env[name]) if name in env else None

    def yes(value):
        return None if value is None else bool(value)

    amount = tx.get("amount")
    facts = {
        "journey": event_type,
        "score": float(score),
        "tx.amount": float(amount) if isinstance(amount, (int, float)) and not isinstance(amount, bool) else None,
        "tx.currency": tx.get("currency"),
        "tx.is_new_payee": bool(tx.get("is_new_beneficiary")) if event_type in config.PAYMENT_EVENTS else None,
        "list.mule_account": "mule" in lists, "list.allow_account": "allow" in lists,
        "env.rooted": flag("is_rooted"), "env.emulator": flag("is_emulator"), "env.hooking": flag("has_hooking_framework"),
        "env.debugger": flag("debugger_attached"), "env.remote_control": flag("active_remote_software"),
        "env.remote_access_installed": flag("remote_access_installed"), "env.screen_sharing": flag("screen_sharing"),
        "env.in_call": in_call, "env.call_seconds": env.get("call_seconds"), "env.vpn": flag("vpn"),
        "env.mock_location": flag("mock_location"), "env.sim_changed": flag("sim_changed"), "env.roaming": flag("roaming"),
        "env.developer_options": flag("developer_options"), "env.keyboard_changed": flag("keyboard_changed"),
        "env.unknown_accessibility_service": flag("unknown_accessibility_service"), "env.hotspot": flag("hotspot"),
        "env.network": env.get("network_type"), "env.app_install_age_days": env.get("app_install_age_days"),
        "env.background_switches": env.get("background_switches"),
        "device.integrity": session.integrity,
        "session.owner_confirmed": bool(getattr(session, "owner_proved", False)),
        "session.location_jump": bool(session.location_jump), "session.ip_changes": session.ip_changes,
        "beh.hesitation": feats.get("ft_hesitation_index"), "beh.paste_in_payee": feats.get("ft_paste_beneficiary_count"),
        "beh.typing_cpm": feats.get("ft_typing_speed_cpm"), "beh.touches": feats.get("ft_touch_count"),
        "beh.swipes": feats.get("ft_swipe_count"), "beh.tap_hold_ms": feats.get("ft_tap_duration_mean_ms"),
        "beh.long_presses": feats.get("ft_long_press_count"), "beh.autofills": feats.get("ft_autofill_count"),
        "beh.lying_flat": yes(feats.get("ft_lying_flat")), "beh.walking": yes(feats.get("ft_walking")),
        "profile.match": (baseline or {}).get("match_score"), "profile.sessions": (baseline or {}).get("sessions"),
        "ml.anomalous": bool(ml["anomalous"]) if ml and ml.get("status") == "ACTIVE" else None,
    }
    for name in ("payments_24h", "amount_24h", "new_payees_24h", "distinct_payees_7d", "device_customers_7d", "payee_customers_7d"):
        facts["vel." + name] = v.get(name)
    return {k: (float(val) if isinstance(val, int) and not isinstance(val, bool) else val)
            for k, val in facts.items() if val is not None}


DEGRADED_REASONS = ("REASON_DEGRADED_NO_TELEMETRY", "REASON_DEGRADED_SCORING_ERROR")


def degraded_decision(event_type, tx, reason, denied=()):
    """Answer from the transaction alone when behavior cannot be scored (PRD fail policy).

    A new payee or a large amount steps up; everything else is allowed and logged. Never a BLOCK because
    FortGuard had a problem: that would be worse than asking for a second factor. The one exception is
    the bank's own deny list, which blocks here as it does everywhere.
    """
    assert reason in DEGRADED_REASONS
    tx = tx or {}
    payment = event_type in config.PAYMENT_EVENTS
    amount = tx.get("amount") or 0
    risky = payment and (bool(tx.get("is_new_beneficiary")) or amount >= config.DEGRADED_STEP_UP_AMOUNT)
    score = config.bands_for(event_type)["step_up_from"] if risky else 0
    if denied:
        score = config.SCORE_MAX
    level = "BLOCK" if denied else level_for(score, event_type)
    return {
        "risk_score": score,
        "risk_level": level,
        "action_recommended": config.ACTIONS[level],
        "reason_codes": (["REASON_ON_DENY_LIST"] if denied else []) + [reason],
        "deny_list": sorted(denied),
        "payee_lists": [],
        "velocity": None,
        "shadow_rules": [],
        "threat_details": {"bot_probability": 0.0, "rat_detected": False, "coercion_scam_probability": 0.0,
                           "user_biometric_match_score": None},
        "score_breakdown": [{"reason": reason, "points": score}],
        "baseline": {"status": "NONE", "sessions": 0, "required": config.BASELINE_MIN_SESSIONS,
                     "match_score": None, "match_score_preview": None, "least_typical_features": []},
        "ml": mlmodel.EMPTY,
        "identity": identity_verdict(None, None, None),
        "signals_used": "TRANSACTION_ONLY",
        "scoring_mode": "DEGRADED",
        "model_version": config.MODEL_VERSION,
        "degraded": True,
    }
