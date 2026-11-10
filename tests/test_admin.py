"""Analyst portal endpoints and the dev-only harness."""

import json

import pytest

from fortguard import admin
from fortguard.app import create_app
from fortguard.client import InProcessTransport, enroll_device, run_session
from fortguard.attestation import DEV_AUTHORITY
from fortguard.signing import b64e, key_sha256, public_key_to_b64
from fortguard.simdevice import SimDevice


@pytest.fixture
def dev_api(clock):
    return InProcessTransport(create_app(clock=clock, dev_mode=True))


def get(api, path, auth=True):
    headers = {"X-API-Key": api.api_key} if auth else {}
    r = api.client.get(path, headers=headers)
    return r.status_code, r.get_json(silent=True)


# --- Decisions and devices ----------------------------------------------------------------------------


def test_decisions_need_the_api_key(api):
    assert get(api, "/v1/admin/decisions", auth=False)[0] == 401
    assert get(api, "/v1/admin/devices", auth=False)[0] == 401


def test_decision_is_logged_with_everything_the_portal_shows(api, make_session):
    session = make_session("coached_scam")
    run_session(api, session)
    status, data = get(api, "/v1/admin/decisions")
    assert status == 200 and data["counts"]["total"] == 1
    d = data["decisions"][0]
    assert d["session_id"] == session["session_id"] and d["risk_level"] == "STEP_UP"
    assert d["score_breakdown"] and d["device_integrity"] == "STRONG" and d["event_type"] == "FUNDS_TRANSFER"


def test_full_account_number_is_never_logged(api, make_session):
    session = make_session("genuine")
    run_session(api, session)
    account = session["evaluate"]["transaction_details"]["beneficiary_account"]
    _, data = get(api, "/v1/admin/decisions")
    assert data["decisions"][0]["beneficiary_last4"] == account[-4:]
    assert account not in json.dumps(data)


def test_counts_and_level_filter(api, make_session):
    for scenario in ("genuine", "coached_scam", "bot_scripted"):
        run_session(api, make_session(scenario))
    _, data = get(api, "/v1/admin/decisions")
    assert data["counts"] == {"total": 3, "ALLOW": 1, "STEP_UP": 1, "BLOCK": 1}
    _, blocked = get(api, "/v1/admin/decisions?level=BLOCK")
    assert [d["risk_level"] for d in blocked["decisions"]] == ["BLOCK"]
    assert blocked["counts"]["total"] == 3  # tiles keep showing the overall counts


def test_newest_decision_comes_first(api, make_session, clock):
    run_session(api, make_session("genuine"))
    clock.now += 10
    run_session(api, make_session("coached_scam"))
    _, data = get(api, "/v1/admin/decisions")
    assert [d["risk_level"] for d in data["decisions"]] == ["STEP_UP", "ALLOW"]


def test_repeated_request_id_is_logged_once(api, make_session):
    session = make_session("genuine")
    run_session(api, session)
    api.post("/v1/risk/evaluate", session["evaluate"], auth=True)  # cached by request_id
    assert get(api, "/v1/admin/decisions")[1]["counts"]["total"] == 1


def test_bad_limit_is_a_defined_error(api):
    status, data = get(api, "/v1/admin/decisions?limit=lots")
    assert (status, data["error"]["code"]) == (400, "invalid_request")


def test_decision_log_is_bounded(clock):
    log = admin.DecisionLog(maxlen=3)

    class S:
        device_guid, integrity = "dev_x", "STRONG"

    result = {"risk_score": 1, "risk_level": "ALLOW", "action_recommended": "PROCEED", "reason_codes": [],
              "score_breakdown": [], "threat_details": {}, "signals_used": "X", "model_version": "m"}
    for i in range(10):
        log.record({"session_id": f"s{i}", "user_id": "u", "event_type": "LOGIN"}, S(), result, i)
    assert [d["session_id"] for d in log.snapshot()] == ["s9", "s8", "s7"]


def test_devices_list_and_revoke_shows_in_it(api, enrolled):
    session = enrolled()
    _, data = get(api, "/v1/admin/devices")
    row = data["devices"][0]
    assert row["device_guid"] == session["device"].device_guid and row["status"] == "ACTIVE"
    assert row["integrity_level"] == "STRONG" and "key_sha256" in row and len(row["key_sha256"]) == 16
    api.post(f"/v1/devices/{row['device_guid']}/revoke", {}, auth=True)
    assert get(api, "/v1/admin/devices")[1]["devices"][0]["status"] == "REVOKED"


# --- Pages ---------------------------------------------------------------------------------------------------


def test_portal_page_is_served_and_asks_for_no_data_itself(api):
    r = api.client.get("/portal")
    assert r.status_code == 200 and b"FortGuard Back Office" in r.data


def test_shared_js_is_served_but_other_web_files_are_not(api):
    assert api.client.get("/web/fgcore.js").status_code == 200
    assert api.client.get("/web/phone.html").status_code == 404
    assert api.client.get("/web/../app.py").status_code == 404


# --- Dev mode gating -------------------------------------------------------------------------------------------


@pytest.mark.parametrize("method,path", [("get", "/phone"), ("post", "/v1/dev/attest"),
                                         ("get", "/v1/dev/scenarios"), ("post", "/v1/dev/simulate")])
def test_dev_endpoints_do_not_exist_outside_dev_mode(api, method, path):
    headers = {"X-API-Key": api.api_key}
    assert getattr(api.client, method)(path, headers=headers).status_code == 404


def test_phone_page_is_served_in_dev_mode(dev_api):
    r = dev_api.client.get("/phone")
    assert r.status_code == 200 and b"FortGuard test client" in r.data


def test_dev_attest_token_lets_a_web_device_enroll(dev_api, clock):
    device = SimDevice("browser", platform="Web")
    status, ch = dev_api.post("/v1/devices/challenge", {})
    common = {"device_guid": device.device_guid, "app_id": device.app_id, "platform": "Web",
              "challenge": ch["challenge"], "public_key": device.public_key_b64}
    status, att = dev_api.post("/v1/dev/attest", {**common, "level": "DEVICE"})
    assert status == 200
    status, body = dev_api.post("/v1/devices/enroll", {**common, "attestation": att["attestation"]})
    assert (status, body["integrity_level"]) == (201, "DEVICE")


def test_dev_attest_checks_its_input(dev_api):
    base = {"device_guid": "dev_abcdefgh1234", "app_id": "x", "platform": "Web", "challenge": "c",
            "public_key": SimDevice("a").public_key_b64}
    for change in ({"level": "GOLD"}, {"platform": "Palm"}, {"public_key": "nope"}, {"challenge": ""},
                   {"device_guid": "bad id"}):
        status, _ = dev_api.post("/v1/dev/attest", {**base, **change})
        assert status == 400, change


def test_simulate_runs_a_scenario_and_it_shows_up_in_the_portal(dev_api):
    status, body = dev_api.post("/v1/dev/simulate", {"scenario": "coached_scam", "seed": 4}, auth=True)
    assert status == 200 and body["result"]["risk_level"] == "STEP_UP"
    _, data = get(dev_api, "/v1/admin/decisions")
    assert data["counts"]["total"] == 1 and data["dev_mode"] is True


def test_simulate_validates_and_needs_the_key(dev_api):
    assert dev_api.post("/v1/dev/simulate", {"scenario": "alien"}, auth=True)[0] == 400
    assert dev_api.post("/v1/dev/simulate", {"scenario": "genuine", "seed": "x"}, auth=True)[0] == 400
    assert dev_api.post("/v1/dev/simulate", {"scenario": "genuine"}, auth=False)[0] == 401


def test_web_platform_is_accepted_in_telemetry_environment(api, make_session, resign, clock):
    session = make_session()
    assert enroll_device(api, session["device"], int(clock() * 1000))[0] == 201
    batch = session["batches"][0]
    batch["environment"]["os"] = "Web"
    assert api.post("/v1/telemetry/stream", resign(batch, session))[0] == 202


def test_decision_keeps_the_measured_numbers_and_no_text(api, make_session):
    session = make_session("coached_scam")
    run_session(api, session)
    _, data = get(api, "/v1/admin/decisions")
    feats = data["decisions"][0]["features"]
    assert feats, "the behaviour measured for the decision is stored with it"
    assert all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in feats.values())
    assert "ft_accel_samples" in feats  # always measured; typing values appear only when the phone sends counts
