"""Scenario tests on synthetic labeled sessions.

These prove the rules do what they are written to do. They are not a detection benchmark: the data
is invented, so passing here says nothing about fraud capture or false positives on real traffic.
"""

import pytest

from fortguard.client import run_session
from fortguard.generator import EXPECTED_AT_LEAST, EXPECTED_AT_MOST, ORDER, SCENARIOS


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("seed", range(5))
def test_scenario_lands_in_expected_band(api, make_session, scenario, seed):
    status, body = run_session(api, make_session(scenario, seed))
    assert status == 200
    level = ORDER[body["risk_level"]]
    assert level >= ORDER[EXPECTED_AT_LEAST[scenario]], body
    assert level <= ORDER[EXPECTED_AT_MOST.get(scenario, "BLOCK")], body


def reasons(api, make_session, scenario):
    return set(run_session(api, make_session(scenario))[1]["reason_codes"])


def test_coached_scam_returns_step_up_with_scam_reasons(api, make_session):
    _, body = run_session(api, make_session("coached_scam"))
    assert body["risk_level"] in ("STEP_UP", "BLOCK")
    assert {
        "REASON_ACTIVE_CALL_DURING_PAYMENT",
        "REASON_COGNITIVE_HESITATION_DETECTED",
        "REASON_COACHED_SCAM_PATTERN",
    } <= set(body["reason_codes"])
    assert body["threat_details"]["coercion_scam_probability"] >= 0.8


def test_remote_control_sets_rat_flag(api, make_session):
    _, body = run_session(api, make_session("remote_control"))
    assert body["threat_details"]["rat_detected"] is True
    assert "REASON_REMOTE_ACCESS_TOOL_ACTIVE" in body["reason_codes"]


def test_bot_has_high_bot_probability_and_scripted_reasons(api, make_session):
    _, body = run_session(api, make_session("bot_scripted"))
    assert body["risk_level"] == "BLOCK"
    assert body["threat_details"]["bot_probability"] >= 0.8
    assert {"REASON_SCRIPTED_INPUT", "REASON_PERFECT_LINEAR_SWIPES"} <= set(body["reason_codes"])


def test_rooted_device_is_forced_to_at_least_step_up(api, make_session):
    _, body = run_session(api, make_session("rooted_device"))
    assert body["risk_score"] >= 600
    assert body["risk_level"] == "STEP_UP"


def test_genuine_session_has_no_reasons(api, make_session):
    _, body = run_session(api, make_session("genuine"))
    assert body["reason_codes"] == []
    assert body["risk_score"] == 0


def test_new_payee_alone_is_not_enough_to_step_up(api, make_session):
    _, body = run_session(api, make_session("genuine_new_payee"))
    assert body["reason_codes"] == ["REASON_NEW_BENEFICIARY"]
    assert body["risk_level"] == "ALLOW"


def test_missing_telemetry_with_consent_is_flagged(api, enrolled, resign):
    session = enrolled()
    empty = resign({**session["batches"][0], "touch_events": [], "key_events": [], "ui_events": [],
                    "sensor_data": {}}, session)
    api.post("/v1/telemetry/stream", empty)
    _, body = api.post("/v1/risk/evaluate", session["evaluate"], auth=True)
    assert "REASON_NO_TELEMETRY" in body["reason_codes"]
    assert body["signals_used"] == "ENVIRONMENT_ONLY"


def test_no_consent_session_scored_on_environment_only(api, make_session):
    _, body = run_session(api, make_session("no_consent"))
    assert body["signals_used"] == "ENVIRONMENT_ONLY"
    assert "REASON_NO_TELEMETRY" not in body["reason_codes"]


def test_same_input_gives_same_score(app, make_session):
    from fortguard.client import InProcessTransport

    a = run_session(InProcessTransport(app), make_session("coached_scam", 3))[1]
    from fortguard.app import create_app
    from fortguard.client import InProcessTransport as T

    b = run_session(T(create_app(clock=app.fortguard_store.clock)), make_session("coached_scam", 3))[1]
    for k in ("risk_score", "risk_level", "reason_codes", "threat_details"):
        assert a[k] == b[k]


def test_evaluate_latency_is_far_below_budget(api, make_session):
    """Rules scoring of a full session should sit well inside the 20 ms scoring budget (PRD)."""
    session = make_session("coached_scam")
    _, body = run_session(api, session)
    assert body["latency_ms"] < 20
