"""Per-user behavioral baselines: learning, cold start, anomaly, poisoning protection."""

import pytest

from fortguard import config
from fortguard.client import run_session


def go(api, make_session, scenario, seed, user="usr_baseline1"):
    s = make_session(scenario, seed)
    s["evaluate"]["user_id"] = user
    s["evaluate"].pop("request_id", None)
    return run_session(api, s)[1]


def mature(api, make_session, user="usr_baseline1"):
    for i in range(config.BASELINE_MIN_SESSIONS):
        go(api, make_session, "genuine", 100 + i, user)


def test_baseline_grows_from_none_to_mature(api, make_session):
    first = go(api, make_session, "genuine", 1)
    assert first["baseline"]["status"] == "NONE" and first["threat_details"]["user_biometric_match_score"] is None
    for i in range(config.BASELINE_MIN_SESSIONS - 1):
        b = go(api, make_session, "genuine", 2 + i)
        assert b["baseline"]["status"] == "LEARNING"
    b = go(api, make_session, "genuine", 50)
    assert b["baseline"]["status"] == "MATURE" and b["baseline"]["sessions"] == config.BASELINE_MIN_SESSIONS


def test_own_behavior_matches_well(api, make_session):
    mature(api, make_session)
    b = go(api, make_session, "genuine", 777)
    assert b["threat_details"]["user_biometric_match_score"] >= 0.6
    assert "REASON_BEHAVIORAL_ANOMALY_HIGH" not in b["reason_codes"]


def test_scripted_input_is_anomalous_against_a_mature_baseline(api, make_session):
    mature(api, make_session)
    b = go(api, make_session, "bot_scripted", 5)
    assert b["threat_details"]["user_biometric_match_score"] < config.BASELINE_ANOMALY_BELOW
    assert "REASON_BEHAVIORAL_ANOMALY_HIGH" in b["reason_codes"]
    assert {"reason": "REASON_BEHAVIORAL_ANOMALY_HIGH", "points": 300} in b["score_breakdown"]


def test_cold_start_never_acts_on_the_match(api, make_session):
    for i in range(3):
        go(api, make_session, "genuine", 10 + i)
    b = go(api, make_session, "bot_scripted", 5)
    assert b["baseline"]["status"] == "LEARNING"
    assert b["baseline"]["match_score_preview"] is not None and b["baseline"]["match_score_preview"] < 0.35
    assert b["threat_details"]["user_biometric_match_score"] is None
    assert "REASON_BEHAVIORAL_ANOMALY_HIGH" not in b["reason_codes"]


def test_only_allowed_sessions_are_learned(api, app, make_session):
    go(api, make_session, "bot_scripted", 1)        # BLOCK
    go(api, make_session, "coached_scam", 1)        # STEP_UP
    assert app.fortguard_baselines.profile("usr_baseline1")["sessions"] == 0
    go(api, make_session, "genuine", 1)
    assert app.fortguard_baselines.profile("usr_baseline1")["sessions"] == 1


def test_users_are_isolated(api, app, make_session):
    mature(api, make_session, user="usr_alice001")
    assert app.fortguard_baselines.profile("usr_bob00001")["sessions"] == 0
    assert go(api, make_session, "genuine", 9, user="usr_bob00001")["baseline"]["status"] == "NONE"


def test_window_keeps_only_recent_sessions(api, app, make_session, monkeypatch):
    monkeypatch.setattr(config, "BASELINE_WINDOW", 5)
    for i in range(8):
        go(api, make_session, "genuine", 200 + i)
    assert app.fortguard_baselines.profile("usr_baseline1")["sessions"] == 5


def test_forget_removes_a_session(api, app, make_session):
    s = make_session("genuine", 3)
    s["evaluate"]["user_id"] = "usr_baseline1"
    run_session(api, s)
    assert app.fortguard_baselines.forget(s["session_id"]) == 1
    assert app.fortguard_baselines.profile("usr_baseline1")["sessions"] == 0


def test_no_consent_means_no_baseline_learning(api, app, make_session):
    go(api, make_session, "no_consent", 1)
    assert app.fortguard_baselines.profile("usr_baseline1")["sessions"] == 0


def test_baseline_shows_in_the_back_office_record(api, app, make_session):
    go(api, make_session, "genuine", 1)
    record = app.fortguard_decisions.snapshot()[0]
    assert record["baseline"]["status"] == "NONE"


def _doubting(app, monkeypatch):
    """Makes the profile say every session is unlike the customer, as it would for another person."""
    real = app.fortguard_baselines.assess

    def assess(user_id, feats):
        baseline, _ = real(user_id, feats)
        return dict(baseline, match_score=0.1), True
    monkeypatch.setattr(app.fortguard_baselines, "assess", assess)


def test_someone_else_paying_from_the_phone_is_stepped_up(api, app, make_session, monkeypatch):
    mature(api, make_session)
    _doubting(app, monkeypatch)
    b = go(api, make_session, "genuine", 901)
    assert "REASON_NOT_ACCOUNT_HOLDER" in b["reason_codes"]
    assert b["risk_level"] == "STEP_UP", b                       # one model's doubt is enough on a payment
    assert b["identity"]["verdict"] == "NOT_OWNER_LIKELY"


def sign_in(api, make_session, seed, user="usr_baseline1"):
    s = make_session("genuine", seed)
    s["evaluate"].update(user_id=user, event_type="LOGIN")
    s["evaluate"].pop("transaction_details", None)
    s["evaluate"].pop("request_id", None)
    return run_session(api, s)[1]


def test_doubt_on_a_sign_in_is_reported_but_not_forced(api, app, make_session, monkeypatch):
    for i in range(config.BASELINE_MIN_SESSIONS):
        sign_in(api, make_session, 300 + i)
    _doubting(app, monkeypatch)
    b = sign_in(api, make_session, 902)
    assert "REASON_NOT_ACCOUNT_HOLDER" not in b["reason_codes"]
    assert b["identity"]["verdict"] == "NOT_OWNER_LIKELY"


def test_a_session_judged_not_the_owner_is_not_learned(api, app, make_session, monkeypatch):
    for i in range(config.BASELINE_MIN_SESSIONS):
        sign_in(api, make_session, 300 + i)
    key = "usr_baseline1" + config.PROFILE_SCOPE_SUFFIX
    before = app.fortguard_baselines.profile(key)["sessions"]
    _doubting(app, monkeypatch)
    assert sign_in(api, make_session, 903)["risk_level"] == "ALLOW"
    assert app.fortguard_baselines.profile(key)["sessions"] == before == config.BASELINE_MIN_SESSIONS


def test_sign_ins_and_payments_are_learned_apart(api, app, make_session):
    """The fault this replaces: ten identity checks taught a profile that then judged a payment."""
    for i in range(config.BASELINE_MIN_SESSIONS):
        sign_in(api, make_session, 300 + i)
    assert app.fortguard_baselines.profile("usr_baseline1")["sessions"] == 0
    payment = go(api, make_session, "genuine", 500)
    assert payment["identity"]["verdict"] == "LEARNING" and payment["identity"]["sessions"] == 0
    assert "REASON_NOT_ACCOUNT_HOLDER" not in payment["reason_codes"]
