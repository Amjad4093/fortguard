"""Contract tests: the evaluate and telemetry endpoints match the BRD shapes and error rules."""

import copy

import pytest

from fortguard import config
from fortguard.client import run_session

BRD_RESPONSE_KEYS = {
    "session_id", "risk_score", "risk_level", "action_recommended", "reason_codes", "threat_details",
}
THREAT_KEYS = {"bot_probability", "rat_detected", "coercion_scam_probability", "user_biometric_match_score"}


def test_evaluate_response_matches_brd_shape(api, make_session):
    status, body = run_session(api, make_session("coached_scam"))
    assert status == 200
    assert BRD_RESPONSE_KEYS <= set(body)
    assert set(body["threat_details"]) == THREAT_KEYS
    assert isinstance(body["risk_score"], int) and 0 <= body["risk_score"] <= 1000
    assert body["risk_level"] in ("ALLOW", "STEP_UP", "BLOCK")
    assert body["action_recommended"] == config.ACTIONS[body["risk_level"]]
    assert all(code.startswith("REASON_") for code in body["reason_codes"])
    assert body["degraded"] is False
    assert body["scoring_mode"] == "RULES_ONLY"


def test_brd_example_step_up_action_string(api, make_session):
    _, body = run_session(api, make_session("coached_scam"))
    assert body["risk_level"] == "STEP_UP"
    assert body["action_recommended"] == "CHALLENGE_FIDO2_OR_OTP"


@pytest.mark.parametrize(
    "score,expected",
    [(0, "ALLOW"), (599, "ALLOW"), (600, "STEP_UP"), (899, "STEP_UP"), (900, "BLOCK"), (1000, "BLOCK")],
)
def test_band_edges(score, expected):
    from fortguard.scoring import level_for

    assert level_for(score, "FUNDS_TRANSFER") == expected


def test_score_is_sum_of_breakdown_unless_capped_or_forced(api, make_session):
    _, body = run_session(api, make_session("coached_scam"))
    assert body["risk_score"] == sum(item["points"] for item in body["score_breakdown"])


def test_every_reason_has_a_weight(api, make_session):
    for scenario in ("bot_scripted", "remote_control", "coached_scam", "rooted_device"):
        _, body = run_session(api, make_session(scenario))
        assert set(body["reason_codes"]) <= set(config.WEIGHTS)


def test_evaluate_requires_api_key(api, make_session):
    session = make_session()
    for batch in session["batches"]:
        api.post("/v1/telemetry/stream", batch)
    status, body = api.post("/v1/risk/evaluate", session["evaluate"], auth=False)
    assert status == 401
    assert body["error"]["code"] == "unauthorized"


def test_unknown_session_is_a_defined_error(api, make_session):
    status, body = api.post("/v1/risk/evaluate", make_session()["evaluate"], auth=True)
    assert status == 404
    assert body["error"]["code"] == "unknown_session"


def test_session_cannot_be_evaluated_for_another_user(api, make_session):
    session = make_session()
    run_session(api, session)
    other = copy.deepcopy(session["evaluate"])
    other["user_id"] = "someone_else"
    other.pop("request_id")
    status, body = api.post("/v1/risk/evaluate", other, auth=True)
    assert status == 409
    assert body["error"]["code"] == "session_user_mismatch"


def test_request_id_makes_evaluate_idempotent(api, make_session):
    session = make_session()
    status, first = run_session(api, session)
    status2, second = api.post("/v1/risk/evaluate", session["evaluate"], auth=True)
    assert status == status2 == 200
    assert first == second


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda e: e.pop("user_id"), "invalid_request"),
        (lambda e: e.update(event_type="WIRE_MAGIC"), "invalid_request"),
        (lambda e: e.update(surprise=1), "unknown_field"),
        (lambda e: e["transaction_details"].update(amount="lots"), "invalid_request"),
        (lambda e: e["transaction_details"].update(currency="rupees"), "invalid_request"),
        (lambda e: e.pop("transaction_details"), "invalid_request"),
    ],
)
def test_bad_evaluate_requests_are_rejected(api, make_session, mutate, code):
    session = make_session()
    run_session(api, session)
    bad = copy.deepcopy(session["evaluate"])
    bad.pop("request_id")
    mutate(bad)
    status, body = api.post("/v1/risk/evaluate", bad, auth=True)
    assert status == 400
    assert body["error"]["code"] == code


def test_non_json_body_is_a_defined_error(app):
    r = app.test_client().post("/v1/telemetry/stream", data="not json", content_type="application/json")
    assert r.status_code == 400
    assert r.get_json()["error"]["code"] == "invalid_json"


def test_oversize_body_is_refused(app):
    r = app.test_client().post(
        "/v1/telemetry/stream", data=b"x" * (config.MAX_BODY_BYTES + 10), content_type="application/json"
    )
    assert r.status_code == 413
    assert r.get_json()["error"]["code"] == "body_too_large"


def test_unknown_route_and_method_are_json(app):
    c = app.test_client()
    assert c.get("/nope").get_json()["error"]["code"] == "not_found"
    assert c.get("/v1/risk/evaluate").get_json()["error"]["code"] == "method_not_allowed"


def test_healthz(app):
    assert app.test_client().get("/healthz").get_json()["status"] == "ok"


def test_telemetry_ack_counts(api, enrolled):
    batch = enrolled()["batches"][0]
    status, body = api.post("/v1/telemetry/stream", batch)
    assert status == 202
    assert body["accepted"]["touch"] == len(batch["touch_events"])
    assert body["accepted"]["sensor"] == sum(len(v) for v in batch["sensor_data"].values())
