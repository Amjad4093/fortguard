"""Degraded mode (PRD fail policy) and the bank's feedback API."""

import pytest

from fortguard import config
from fortguard.client import run_session
from fortguard import scoring


def evaluate(api, body):
    return api.post("/v1/risk/evaluate", body, auth=True)


def tx_body(session_id="sess_nodata0001", amount=5000.0, new_payee=False, degraded=True):
    body = {"session_id": session_id, "user_id": "usr_degraded1", "event_type": "FUNDS_TRANSFER",
            "transaction_details": {"amount": amount, "currency": "PKR",
                                    "beneficiary_account": "PK36EXMP00992201029381", "is_new_beneficiary": new_payee}}
    if degraded is not None:
        body["allow_degraded"] = degraded
    return body


# --- Degraded mode -----------------------------------------------------------------------------------

def test_without_permission_missing_telemetry_is_still_an_error(api):
    status, body = evaluate(api, tx_body(degraded=None))
    assert (status, body["error"]["code"]) == (404, "unknown_session")


def test_low_value_known_payee_is_allowed_and_marked_degraded(api):
    status, body = evaluate(api, tx_body())
    assert status == 200
    assert (body["risk_level"], body["degraded"], body["scoring_mode"]) == ("ALLOW", True, "DEGRADED")
    assert body["reason_codes"] == ["REASON_DEGRADED_NO_TELEMETRY"]
    assert body["signals_used"] == "TRANSACTION_ONLY"


@pytest.mark.parametrize("amount,new_payee", [(5000.0, True), (config.DEGRADED_STEP_UP_AMOUNT, False), (900_000.0, True)])
def test_new_payee_or_large_amount_steps_up_never_blocks(api, amount, new_payee):
    _, body = evaluate(api, tx_body(amount=amount, new_payee=new_payee))
    assert body["risk_level"] == "STEP_UP" and body["degraded"] is True


def test_login_without_telemetry_is_allowed(api):
    status, body = evaluate(api, {"session_id": "sess_nodata0002", "user_id": "usr_x1", "event_type": "LOGIN",
                                  "allow_degraded": True})
    assert (status, body["risk_level"]) == (200, "ALLOW")


def test_scoring_failure_falls_back_when_allowed(api, make_session, monkeypatch):
    session = make_session("genuine")
    run_session(api, session)  # enrolls, sends and evaluates once normally
    def boom(*a, **k):
        raise RuntimeError("feature store down")
    monkeypatch.setattr("fortguard.app.score_session", boom)
    body = dict(session["evaluate"]); body.pop("request_id", None); body["allow_degraded"] = True
    status, out = evaluate(api, body)
    assert status == 200 and out["reason_codes"] == ["REASON_DEGRADED_SCORING_ERROR"]


def test_scoring_failure_without_permission_is_a_500(api, make_session, monkeypatch):
    session = make_session("genuine")
    run_session(api, session)
    monkeypatch.setattr("fortguard.app.score_session", lambda *a, **k: 1 / 0)
    body = dict(session["evaluate"]); body.pop("request_id", None)
    status, out = evaluate(api, body)
    assert (status, out["error"]["code"]) == (500, "internal_error")


def test_degraded_step_up_opens_a_case(api, app):
    evaluate(api, tx_body(new_payee=True))
    cases = app.fortguard_backoffice.q("SELECT risk_level FROM cases")
    assert [c["risk_level"] for c in cases] == ["STEP_UP"]


def test_allow_degraded_must_be_boolean(api):
    status, body = evaluate(api, tx_body(degraded="yes"))
    assert (status, body["error"]["code"]) == (400, "invalid_request")


def test_degraded_never_blocks_even_with_strict_bands(api, monkeypatch):
    config.BANDS["default"].update({"step_up_from": 50, "block_from": 60})
    _, body = evaluate(api, tx_body(new_payee=True))
    assert body["risk_level"] == "STEP_UP"


# --- Feedback -------------------------------------------------------------------------------------------

def feedback(api, session_id, label, **extra):
    return api.post("/v1/feedback", {"session_id": session_id, "label": label, **extra}, auth=True)


def test_feedback_needs_the_api_key(api):
    status, _ = api.post("/v1/feedback", {"session_id": "sess_abcdefgh", "label": "FRAUD"}, auth=False)
    assert status == 401


def test_feedback_for_unknown_session(api):
    status, body = feedback(api, "sess_neverseen1", "FRAUD")
    assert (status, body["error"]["code"]) == (404, "unknown_session")


@pytest.mark.parametrize("body", [
    {"session_id": "sess_abcdefgh", "label": "MAYBE"},
    {"session_id": "sess_abcdefgh"},
    {"session_id": "sess_abcdefgh", "label": "FRAUD", "extra": 1},
    {"session_id": "sess_abcdefgh", "label": "FRAUD", "note": "x" * 501},
])
def test_feedback_validation(api, body):
    assert api.post("/v1/feedback", body, auth=True)[0] == 400


def test_missed_fraud_opens_a_confirmed_case_and_cleans_the_baseline(api, app, make_session):
    session = make_session("genuine")
    run_session(api, session)                       # ALLOW, learned into the baseline
    user = session["evaluate"]["user_id"]
    assert app.fortguard_baselines.profile(user)["sessions"] == 1
    status, out = feedback(api, session["session_id"], "FRAUD", source="core-banking", note="customer reported")
    assert status == 201 and out["decided_level"] == "ALLOW" and out["baseline_sessions_removed"] == 1
    case = app.fortguard_backoffice.q("SELECT status FROM cases WHERE id=?", (out["case_id"],))[0]
    assert case["status"] == "CONFIRMED_FRAUD"
    assert app.fortguard_baselines.profile(user)["sessions"] == 0


def test_fraud_on_a_flagged_session_confirms_its_case(api, app, make_session):
    session = make_session("coached_scam")
    run_session(api, session)
    out = feedback(api, session["session_id"], "FRAUD")[1]
    assert out["decided_level"] == "STEP_UP"
    assert app.fortguard_backoffice.q("SELECT status FROM cases")[0]["status"] == "CONFIRMED_FRAUD"


def test_genuine_on_a_flagged_session_marks_false_positive(api, app, make_session):
    session = make_session("coached_scam")
    run_session(api, session)
    feedback(api, session["session_id"], "GENUINE")
    assert app.fortguard_backoffice.q("SELECT status FROM cases")[0]["status"] == "FALSE_POSITIVE"


def test_feedback_is_counted_in_the_overview_and_audited(api, app, make_session):
    caught, missed, genuine_flagged = make_session("bot_scripted", 1), make_session("genuine", 2), make_session("coached_scam", 3)
    for s in (caught, missed, genuine_flagged):
        run_session(api, s)
    feedback(api, caught["session_id"], "FRAUD")
    feedback(api, missed["session_id"], "FRAUD")
    feedback(api, genuine_flagged["session_id"], "GENUINE")
    from fortguard.backoffice import feedback_summary
    assert feedback_summary(app.fortguard_backoffice) == {
        "fraud_reported": 2, "fraud_caught": 1, "fraud_missed": 1, "genuine_reported": 1, "genuine_challenged": 1}
    actions = [r["action"] for r in app.fortguard_backoffice.q("SELECT action FROM audit")]
    assert actions.count("feedback") == 3
