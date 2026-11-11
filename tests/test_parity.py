"""Signals and controls added after comparing with the platform team's catalogue: new device facts,
the debugger and SIM-change rules, and the bank's deny list. Each is checked end to end through the API."""

import copy

import pytest

from fortguard.app import create_app
from fortguard.client import InProcessTransport, run_session

ADMIN_PW = "admin-test-password"


@pytest.fixture
def bo_app(clock):
    return create_app(clock=clock, admin_password=ADMIN_PW, dev_mode=True)


@pytest.fixture
def api(bo_app):
    return InProcessTransport(bo_app)


class Portal:
    def __init__(self, app, token=None):
        self.c, self.token = app.test_client(), token

    def call(self, method, path, json=None):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        r = getattr(self.c, method)(path, json=json, headers=headers)
        return r.status_code, r.get_json(silent=True)

    def login(self, username, password):
        status, body = self.call("post", "/v1/auth/login", {"username": username, "password": password})
        if status == 200:
            self.token = body["token"]
        return status, body


@pytest.fixture
def admin(bo_app):
    p = Portal(bo_app)
    assert p.login("admin", ADMIN_PW)[0] == 200
    return p


def with_env(session, **facts):
    """The same session with these environment facts set in every batch, signed again by its device."""
    def signed(batch):
        payload = copy.deepcopy({k: v for k, v in batch.items() if k != "signature"})
        payload["environment"].update(facts)
        return session["device"].sign(payload)
    session["batches"] = [signed(b) for b in session["batches"]]
    return session


# --- Device facts --------------------------------------------------------------------------------------

FACTS = dict(developer_options=True, screen_reader=True, unknown_accessibility_service=True, remote_access_installed=True,
             roaming=True, keyboard_changed=True, font_scale=1.3, call_seconds=95, background_switches=2,
             screens_visited=4, tz_offset_minutes=300, security_patch="2026-09-05", carrier="41001",
             call_direction="incoming")


def test_context_facts_are_accepted_recorded_and_never_a_reason_on_their_own(api, admin, make_session):
    s = with_env(make_session("genuine", 1), **FACTS)
    status, body = run_session(api, s)
    assert status == 200, body
    assert body["risk_level"] == "ALLOW" and body["reason_codes"] == [], body
    shown = admin.call("get", "/v1/bo/decisions")[1]["decisions"][0]["environment"]
    for name, value in FACTS.items():
        assert shown[name] == value, name


def test_a_remote_access_app_merely_installed_does_not_raise_the_remote_access_reason(api, make_session):
    s = with_env(make_session("genuine_new_payee", 1), remote_access_installed=True)
    assert "REASON_REMOTE_ACCESS_TOOL_ACTIVE" not in run_session(api, s)[1]["reason_codes"]


@pytest.mark.parametrize("fact,value", [
    ("security_patch", "September 2026"), ("carrier", "Jazz"), ("carrier", "4100"), ("call_direction", "sideways"),
    ("font_scale", 9.0), ("call_seconds", -1), ("tz_offset_minutes", 5000), ("debugger_attached", "yes"),
    ("screens_visited", 1.5),
])
def test_a_malformed_fact_is_refused(api, make_session, fact, value):
    s = with_env(make_session("genuine", 2), **{fact: value})
    with pytest.raises(RuntimeError, match="telemetry rejected: 400"):
        run_session(api, s)


def test_an_older_app_that_sends_none_of_the_new_facts_still_works(api, admin, make_session):
    status, body = run_session(api, make_session("genuine", 3))
    assert status == 200 and body["risk_level"] == "ALLOW"
    env = admin.call("get", "/v1/bo/decisions")[1]["decisions"][0]["environment"]
    assert "debugger_attached" not in env and "sim_changed" not in env   # "not reported", never a false "no"


def test_a_fact_seen_once_stays_for_the_session(api, admin, make_session):
    s = make_session("genuine", 4)
    first = copy.deepcopy({k: v for k, v in s["batches"][0].items() if k != "signature"})
    first["environment"]["keyboard_changed"] = True
    s["batches"][0] = s["device"].sign(first)
    run_session(api, with_env_after_first(s, keyboard_changed=False))
    assert admin.call("get", "/v1/bo/decisions")[1]["decisions"][0]["environment"]["keyboard_changed"] is True


def with_env_after_first(session, **facts):
    def signed(batch):
        payload = copy.deepcopy({k: v for k, v in batch.items() if k != "signature"})
        payload["environment"].update(facts)
        return session["device"].sign(payload)
    session["batches"] = session["batches"][:1] + [signed(b) for b in session["batches"][1:]]
    return session


# --- Debugger and SIM change ---------------------------------------------------------------------------

def test_a_debugger_on_the_app_forces_at_least_a_step_up(api, make_session):
    status, body = run_session(api, with_env(make_session("genuine", 5), debugger_attached=True))
    assert status == 200
    assert "REASON_DEBUGGER_ATTACHED" in body["reason_codes"]
    assert body["risk_level"] in ("STEP_UP", "BLOCK"), body


def test_a_sim_change_alone_is_noted_but_allowed(api, make_session):
    status, body = run_session(api, with_env(make_session("genuine", 6), sim_changed=True))
    assert body["reason_codes"] == ["REASON_SIM_CHANGED"], body
    assert body["risk_level"] == "ALLOW"


def test_a_sim_change_with_a_new_payee_is_the_sim_swap_pattern_and_steps_up(api, make_session):
    status, body = run_session(api, with_env(make_session("genuine_new_payee", 6), sim_changed=True))
    assert {"REASON_SIM_CHANGED", "REASON_SIM_SWAP_PATTERN", "REASON_NEW_BENEFICIARY"} <= set(body["reason_codes"]), body
    assert body["risk_level"] == "STEP_UP", body


# --- Deny list -----------------------------------------------------------------------------------------

def deny(admin, kind, value, **more):
    return admin.call("post", "/v1/bo/deny-list", {"kind": kind, "value": value, "reason": "confirmed mule account", **more})


def test_a_denied_payee_account_blocks_an_otherwise_clean_payment(api, admin, make_session):
    s = make_session("genuine", 7)
    account = s["evaluate"]["transaction_details"]["beneficiary_account"]
    assert deny(admin, "account", account)[0] == 201
    status, body = run_session(api, s)
    assert status == 200
    assert body["risk_level"] == "BLOCK" and body["risk_score"] == 1000, body
    assert body["reason_codes"][0] == "REASON_ON_DENY_LIST" and body["deny_list"] == ["account"]


def test_spacing_and_case_do_not_let_an_account_slip_past_the_list(api, admin, make_session):
    s = make_session("genuine", 8)
    account = s["evaluate"]["transaction_details"]["beneficiary_account"]
    spaced = " ".join(account[i:i + 4] for i in range(0, len(account), 4)).lower()
    assert deny(admin, "account", spaced)[0] == 201
    assert run_session(api, s)[1]["risk_level"] == "BLOCK"


@pytest.mark.parametrize("kind", ["customer", "device"])
def test_a_denied_customer_or_device_is_blocked(api, admin, make_session, kind):
    s = make_session("genuine", 9)
    value = s["evaluate"]["user_id"] if kind == "customer" else s["device"].device_guid
    assert deny(admin, kind, value)[0] == 201
    body = run_session(api, s)[1]
    assert body["risk_level"] == "BLOCK" and body["deny_list"] == [kind], body


def test_nobody_else_is_affected_by_a_deny_entry(api, admin, make_session):
    assert deny(admin, "account", "PK00DENY0000000000001234")[0] == 201
    assert run_session(api, make_session("genuine", 10))[1]["risk_level"] == "ALLOW"


def test_the_list_shows_only_the_last_four_characters_of_an_account(admin):
    assert deny(admin, "account", "PK36SCBL0000001123456702")[0] == 201
    status, body = admin.call("get", "/v1/bo/deny-list")
    entry = body["entries"][0]
    assert entry["label"] == "••••6702" and "PK36SCBL" not in str(body)
    assert entry["added_by"] == "admin" and entry["expired"] is False


def test_an_entry_expires(api, admin, make_session, clock):
    s = make_session("genuine", 11)
    assert deny(admin, "customer", s["evaluate"]["user_id"], expires_days=1)[0] == 201
    clock.now += 2 * 86_400
    assert admin.login("admin", ADMIN_PW)[0] == 200          # the first sign-in has timed out by now
    assert admin.call("get", "/v1/bo/deny-list")[1]["entries"][0]["expired"] is True
    s2 = make_session("genuine", 11)
    s2["evaluate"]["user_id"] = s["evaluate"]["user_id"]
    assert run_session(api, s2)[1]["risk_level"] == "ALLOW"


def test_removing_an_entry_lifts_the_block_and_both_changes_are_audited(api, admin, make_session):
    s = make_session("genuine", 12)
    entry = deny(admin, "customer", s["evaluate"]["user_id"])[1]["entries"][0]
    assert admin.call("delete", f"/v1/bo/deny-list/{entry['id']}")[0] == 200
    assert run_session(api, s)[1]["risk_level"] == "ALLOW"
    actions = [a["action"] for a in admin.call("get", "/v1/bo/audit")[1]["audit"]]
    assert "deny_add" in actions and "deny_remove" in actions
    assert admin.call("delete", f"/v1/bo/deny-list/{entry['id']}")[0] == 404


def test_bad_entries_are_refused(admin):
    assert admin.call("post", "/v1/bo/deny-list", {"kind": "phone", "value": "x", "reason": "because"})[0] == 400
    assert admin.call("post", "/v1/bo/deny-list", {"kind": "ip", "value": "not-an-ip", "reason": "because"})[0] == 400
    assert admin.call("post", "/v1/bo/deny-list", {"kind": "account", "value": "PK36SCBL0000001123456702", "reason": "x"})[0] == 400
    assert deny(admin, "ip", "203.0.113.9", expires_days=0)[0] == 400
    assert deny(admin, "ip", "203.0.113.9")[0] == 201
    assert deny(admin, "ip", "203.0.113.9")[0] == 409


def test_a_viewer_can_read_the_list_but_not_change_it(admin, bo_app):
    assert admin.call("post", "/v1/bo/users", {"username": "vera", "password": "long-enough-pw", "role": "viewer"})[0] == 201
    viewer = Portal(bo_app)
    assert viewer.login("vera", "long-enough-pw")[0] == 200
    assert viewer.call("get", "/v1/bo/deny-list")[0] == 200
    assert deny(viewer, "ip", "203.0.113.9")[0] == 403


def test_the_deny_list_blocks_even_when_scoring_falls_back(api, admin):
    assert deny(admin, "customer", "usr_denied01")[0] == 201
    status, body = api.post("/v1/risk/evaluate", {
        "session_id": "sess_never_seen_1", "user_id": "usr_denied01", "event_type": "LOGIN", "allow_degraded": True}, auth=True)
    assert status == 200, body
    assert body["risk_level"] == "BLOCK" and body["reason_codes"][0] == "REASON_ON_DENY_LIST", body


# --- Tap offset, autofill and hotspot through the API --------------------------------------------------

def test_tap_offset_autofill_and_hotspot_are_accepted_and_shown(api, admin, make_session):
    s = make_session("genuine", 21)
    def signed(i, batch):
        payload = copy.deepcopy({k: v for k, v in batch.items() if k != "signature"})
        payload["environment"]["hotspot"] = True
        for e in payload.get("touch_events", []):
            if e["event_type"] == "DOWN":
                e["tdx"], e["tdy"] = 0.6, 0.8
        if i == 0:
            payload.setdefault("ui_events", []).append({"event_type": "AUTOFILL", "field": "other", "ts": payload["timestamp_ms"]})
        return s["device"].sign(payload)
    s["batches"] = [signed(i, b) for i, b in enumerate(s["batches"])]
    status, body = run_session(api, s)
    assert status == 200 and body["risk_level"] == "ALLOW", body
    shown = admin.call("get", "/v1/bo/decisions")[1]["decisions"][0]
    assert shown["environment"]["hotspot"] is True
    assert shown["features"]["ft_tap_offset_mean"] == pytest.approx(1.0)
    assert shown["features"]["ft_autofill_count"] == 1


def test_half_a_tap_offset_is_refused(api, make_session):
    s = make_session("genuine", 22)
    payload = copy.deepcopy({k: v for k, v in s["batches"][0].items() if k != "signature"})
    down = next(e for e in payload["touch_events"] if e["event_type"] == "DOWN")
    down["tdx"] = 0.2
    s["batches"][0] = s["device"].sign(payload)
    with pytest.raises(RuntimeError, match="telemetry rejected: 400"):
        run_session(api, s)
