"""The bank's own rules: the expression language, shadow mode, and the second-person approval."""

import pytest

from fortguard import rulelang
from fortguard.app import create_app
from fortguard.client import InProcessTransport, run_session

ADMIN_PW = "admin-test-password"
FACTS = {"journey": "FUNDS_TRANSFER", "score": 150.0, "tx.amount": 250000.0, "tx.currency": "PKR", "tx.is_new_payee": True,
         "env.in_call": True, "env.vpn": False, "vel.new_payees_24h": 2.0, "list.mule_account": False,
         "beh.hesitation": 0.7, "device.integrity": "STRONG"}


def holds(text, facts=FACTS):
    return rulelang.evaluate(rulelang.compile_rule(text), facts)


# --- The language --------------------------------------------------------------------------------------

@pytest.mark.parametrize("text,want", [
    ("tx.amount >= 250000", True), ("tx.amount > 250000", False), ("tx.amount == 250000 and tx.is_new_payee", True),
    ("tx.is_new_payee and env.in_call", True), ("tx.is_new_payee && env.vpn", False), ("env.vpn || env.in_call", True),
    ("not env.vpn", True), ("!env.in_call", False), ("not (env.vpn or list.mule_account)", True),
    ("journey == \"FUNDS_TRANSFER\"", True), ("journey != 'LOGIN'", True), ("journey in (\"LOGIN\", \"SIGN_UP\")", False),
    ("journey in ('FUNDS_TRANSFER', 'ADD_PAYEE')", True), ("vel.new_payees_24h in (1, 2, 3)", True),
    ("tx.amount / 1000 >= 250", True), ("tx.amount * 2 - 1 > 499998", True), ("score + 100 < 200", False),
    ("tx.amount >= 100000 and (env.in_call or env.vpn) and beh.hesitation > 0.5", True),
    ("-score < 0", True), ("env.in_call == true", True), ("env.vpn == false", True),
    ("env.vpn or env.in_call and tx.amount < 5", False),          # 'and' binds tighter than 'or'
])
def test_conditions_evaluate_as_written(text, want):
    assert holds(text) is want


@pytest.mark.parametrize("text", [
    "env.rooted", "not env.rooted", "env.rooted == false", "beh.typing_cpm > 0", "beh.typing_cpm < 100000",
    "profile.match < 0.5", "not (profile.match >= 0.5)", "tx.amount / vel.payments_24h > 1", "env.network == 'wifi'",
    "env.network != 'wifi'", "env.call_seconds in (1, 2)", "tx.amount / (score - 150) > 1",
])
def test_a_fact_with_no_value_never_makes_a_rule_fire(text):
    assert holds(text) is False


def test_a_missing_fact_does_not_stop_the_other_side_of_an_or():
    assert holds("env.rooted or env.in_call") is True


@pytest.mark.parametrize("text,part", [
    ("", "write a condition"), ("   ", "write a condition"), ("tx.amount", "must be true or false"),
    ("tx.amount >", "ends too early"), ("tx.amount >= ", "ends too early"), ("(tx.amount > 1", "ends too early"),
    ("tx.amount > 1)", "unexpected ')'"), ("tx.amout > 1", "unknown name 'tx.amout'"),
    ("tx.amount > 'big'", "compares a number with a text"), ("journey > 'A'", "only works on numbers"),
    ("env.vpn and tx.amount", "needs a true/false condition"), ("not tx.amount", "needs a true/false condition"),
    ("journey in (1, 2)", "must hold text values"), ("journey in (journey)", "may only hold numbers and quoted text"),
    ("env.vpn + 1 > 0", "only works on numbers"), ("tx.amount > 1 ; drop", "cannot read"),
    ("__import__('os').system('id')", "cannot read"), ("tx.amount.__class__ == 1", "unknown name"),
    ("open('/etc/passwd')", "unknown name"), ("tx.amount > 1 if 1 else 2", "unexpected 'if'"),
    ("x" * 700, "longer than"), ("(" * 40 + "env.vpn" + ")" * 40, "nested too deeply"),
])
def test_bad_conditions_are_refused_with_a_message_for_the_editor(text, part):
    with pytest.raises(rulelang.RuleError) as err:
        rulelang.compile_rule(text)
    assert part in str(err.value), str(err.value)


def test_division_by_zero_is_treated_as_no_value():
    assert holds("tx.amount / (score - 150) >= 0") is False


def test_every_documented_name_is_usable_and_typed():
    for name, (kind, about) in rulelang.VARIABLES.items():
        probe = name if kind == rulelang.BOOL else (f"{name} >= 0" if kind == rulelang.NUMBER else f"{name} == 'x'")
        rulelang.compile_rule(probe)
        assert len(about) > 10


def test_names_used_lists_what_a_condition_reads():
    tree = rulelang.compile_rule("tx.amount > 5 and (env.vpn or journey in ('LOGIN'))")
    assert rulelang.names_used(tree) == {"tx.amount", "env.vpn", "journey"}


# --- Through the API -----------------------------------------------------------------------------------

@pytest.fixture
def bo_app(clock):
    return create_app(clock=clock, admin_password=ADMIN_PW, dev_mode=True)


@pytest.fixture
def api(bo_app):
    return InProcessTransport(bo_app)


class Portal:
    def __init__(self, app):
        self.c, self.token = app.test_client(), None

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


def user(bo_app, admin, name, role):
    assert admin.call("post", "/v1/bo/users", {"username": name, "password": "long-enough-pw", "role": role})[0] == 201
    p = Portal(bo_app)
    assert p.login(name, "long-enough-pw")[0] == 200
    return p


BIG_NEW_PAYEE = {"name": "big_new_payee", "description": "Large payment to a new payee",
                 "expression": "tx.amount >= 200000 and tx.is_new_payee", "points": 500}


def create(portal, **changes):
    return portal.call("post", "/v1/bo/custom-rules", {**BIG_NEW_PAYEE, **changes})


def decide(api, make_session, scenario="genuine_new_payee", seed=1):
    status, body = run_session(api, make_session(scenario, seed))
    assert status == 200, body
    return body


def test_a_new_rule_runs_in_shadow_and_changes_nothing(api, admin, make_session):
    status, out = create(admin)
    assert status == 201 and out["rule"]["mode"] == "shadow" and out["rule"]["pending"] is None
    assert out["rule"]["code"] == "CUSTOM_BIG_NEW_PAYEE"
    body = decide(api, make_session)
    assert body["risk_score"] == 150 and body["risk_level"] == "ALLOW" and body["reason_codes"] == ["REASON_NEW_BENEFICIARY"]
    assert body["shadow_rules"] == [{"rule": "big_new_payee", "would_score": 650, "would_level": "STEP_UP"}]
    assert decide(api, make_session, "genuine", 2)["shadow_rules"] == []          # not a new payee: no hit
    report = admin.call("get", "/v1/bo/custom-rules")[1]["report"]
    assert report["decisions"] == 2
    assert report["rules"]["big_new_payee"]["shadow_hits"] == 1
    assert report["rules"]["big_new_payee"]["would_change"] == {"ALLOW->STEP_UP": 1}


def test_going_live_needs_a_second_admin(api, admin, bo_app, make_session):
    rule = create(admin, mode="live")[1]["rule"]
    assert rule["mode"] == "shadow" and rule["pending"]["mode"] == "live" and rule["pending"]["requested_by"] == "admin"
    assert decide(api, make_session)["risk_score"] == 150                           # still shadow while it waits
    status, body = admin.call("post", f"/v1/bo/custom-rules/{rule['id']}/approve")
    assert status == 403 and body["error"]["code"] == "needs_second_person"
    second = user(bo_app, admin, "second.admin", "admin")
    status, out = second.call("post", f"/v1/bo/custom-rules/{rule['id']}/approve")
    assert status == 200 and out["rule"]["mode"] == "live" and out["rule"]["pending"] is None
    assert out["rule"]["approved_by"] == "second.admin"
    live = decide(api, make_session, seed=3)
    assert live["risk_score"] == 650 and live["risk_level"] == "STEP_UP"
    assert live["reason_codes"] == ["CUSTOM_BIG_NEW_PAYEE", "REASON_NEW_BENEFICIARY"]
    assert {"reason": "CUSTOM_BIG_NEW_PAYEE", "points": 500, "custom": True} in live["score_breakdown"]
    assert live["shadow_rules"] == []
    actions = [a["action"] for a in admin.call("get", "/v1/bo/audit")[1]["audit"]]
    assert "rule_create" in actions and "rule_approve" in actions


def test_an_analyst_can_write_a_rule_but_not_approve_one(admin, bo_app):
    analyst = user(bo_app, admin, "ana.lyst", "analyst")
    rule = create(analyst, mode="live")[1]["rule"]
    assert analyst.call("post", f"/v1/bo/custom-rules/{rule['id']}/approve")[0] == 403
    assert analyst.call("post", f"/v1/bo/custom-rules/{rule['id']}/retire")[0] == 403
    assert admin.call("post", f"/v1/bo/custom-rules/{rule['id']}/approve")[1]["rule"]["mode"] == "live"
    viewer = user(bo_app, admin, "vera.view", "viewer")
    assert viewer.call("get", "/v1/bo/custom-rules")[0] == 200 and create(viewer, name="by_viewer")[0] == 403


def test_a_floor_lifts_the_decision_without_extra_points(api, admin, bo_app, make_session):
    rule = create(admin, name="new_payee_block", points=0, floor="BLOCK", mode="live")[1]["rule"]
    user(bo_app, admin, "second.admin", "admin").call("post", f"/v1/bo/custom-rules/{rule['id']}/approve")
    body = decide(api, make_session)
    assert body["risk_score"] == 900 and body["risk_level"] == "BLOCK"
    assert {"reason": "CUSTOM_NEW_PAYEE_BLOCK", "points": 750, "custom": True} in body["score_breakdown"]


def test_a_shadow_rule_is_edited_at_once_and_a_live_one_waits(api, admin, bo_app, make_session):
    second = user(bo_app, admin, "second.admin", "admin")
    rule = create(admin)[1]["rule"]
    edit = {k: BIG_NEW_PAYEE[k] for k in ("description", "expression")} | {"points": 300}
    out = admin.call("put", f"/v1/bo/custom-rules/{rule['id']}", edit)[1]["rule"]
    assert out["points"] == 300 and out["pending"] is None
    # Promote, approve, then change the live rule: the change waits and the old rule keeps running.
    assert admin.call("put", f"/v1/bo/custom-rules/{rule['id']}", edit | {"mode": "live"})[1]["rule"]["pending"]["mode"] == "live"
    assert second.call("post", f"/v1/bo/custom-rules/{rule['id']}/approve")[0] == 200
    waiting = second.call("put", f"/v1/bo/custom-rules/{rule['id']}", edit | {"mode": "live", "points": 800})[1]["rule"]
    assert waiting["points"] == 300 and waiting["pending"]["points"] == 800
    assert decide(api, make_session)["risk_score"] == 450
    assert second.call("post", f"/v1/bo/custom-rules/{rule['id']}/approve")[0] == 403      # second asked this time
    assert admin.call("post", f"/v1/bo/custom-rules/{rule['id']}/approve")[1]["rule"]["points"] == 800
    assert decide(api, make_session, seed=4)["risk_score"] == 950


def test_a_request_can_be_rejected(admin, bo_app):
    rule = create(admin, mode="live")[1]["rule"]
    out = admin.call("post", f"/v1/bo/custom-rules/{rule['id']}/reject")[1]["rule"]
    assert out["pending"] is None and out["mode"] == "shadow"
    assert admin.call("post", f"/v1/bo/custom-rules/{rule['id']}/reject")[0] == 400
    assert admin.call("post", f"/v1/bo/custom-rules/{rule['id']}/approve")[0] == 400


def test_retiring_stops_a_rule_at_once_and_restoring_brings_it_back_in_shadow(api, admin, bo_app, make_session):
    rule = create(admin, mode="live")[1]["rule"]
    user(bo_app, admin, "second.admin", "admin").call("post", f"/v1/bo/custom-rules/{rule['id']}/approve")
    assert decide(api, make_session)["risk_score"] == 650
    assert admin.call("post", f"/v1/bo/custom-rules/{rule['id']}/retire")[1]["rule"]["retired"] is True
    after = decide(api, make_session, seed=5)
    assert after["risk_score"] == 150 and after["shadow_rules"] == []
    assert admin.call("put", f"/v1/bo/custom-rules/{rule['id']}", {k: BIG_NEW_PAYEE[k] for k in ("description", "expression", "points")})[0] == 400
    restored = admin.call("post", f"/v1/bo/custom-rules/{rule['id']}/restore")[1]["rule"]
    assert restored["retired"] is False and restored["mode"] == "shadow"
    assert decide(api, make_session, seed=6)["shadow_rules"][0]["rule"] == "big_new_payee"


def test_a_rule_only_applies_to_its_journeys(api, admin, make_session):
    create(admin, name="logins_only", expression="score >= 0", journeys=["LOGIN"])
    assert decide(api, make_session)["shadow_rules"] == []
    s = make_session("genuine", 7)
    s["evaluate"]["event_type"] = "LOGIN"
    s["evaluate"].pop("transaction_details")
    assert run_session(api, s)[1]["shadow_rules"][0]["rule"] == "logins_only"


def test_rules_survive_a_restart(tmp_path, clock, make_session):
    path = str(tmp_path / "fortguard.db")
    first = create_app(clock=clock, admin_password=ADMIN_PW, dev_mode=True, db_path=path)
    p = Portal(first)
    p.login("admin", ADMIN_PW)
    assert create(p)[0] == 201
    again = create_app(clock=clock, admin_password=ADMIN_PW, dev_mode=True, db_path=path)
    body = run_session(InProcessTransport(again), make_session("genuine_new_payee", 8))[1]
    assert body["shadow_rules"][0]["rule"] == "big_new_payee"


@pytest.mark.parametrize("change,part", [
    ({"name": "Bad Name"}, "name must be"), ({"name": "ab"}, "name must be"), ({"description": "x"}, "describe the rule"),
    ({"expression": "tx.amout > 1"}, "unknown name"), ({"expression": "tx.amount"}, "must be true or false"),
    ({"points": -1}, "points must be"), ({"points": 1001}, "points must be"), ({"points": 1.5}, "points must be"),
    ({"points": 0}, "can never change a decision"), ({"floor": "HOLD"}, "floor must be"),
    ({"journeys": ["MARS"]}, "journeys must be"), ({"journeys": "LOGIN"}, "journeys must be"),
    ({"mode": "on"}, "mode must be"), ({"sql": "drop"}, "may only carry"),
])
def test_a_bad_rule_is_refused_with_a_reason(admin, change, part):
    status, body = create(admin, **change)
    assert status == 400 and part in body["error"]["message"], body


def test_a_name_can_be_used_once(admin):
    assert create(admin)[0] == 201
    assert create(admin)[0] == 409


def test_a_draft_can_be_tried_on_past_decisions_without_saving_it(api, admin, make_session):
    for seed, scenario in enumerate(("genuine", "genuine_new_payee", "genuine_new_payee", "coached_scam")):
        decide(api, make_session, scenario, seed)
    status, out = admin.call("post", "/v1/bo/custom-rules/test", {"expression": "tx.is_new_payee and tx.amount >= 200000", "points": 500})
    assert status == 200, out
    assert out["decisions"] == 4 and out["hits"] == 3 and out["hit_rate"] == 0.75
    assert out["by_level"] == {"ALLOW": 2, "STEP_UP": 1, "BLOCK": 0}
    assert out["would_change"] == {"ALLOW->STEP_UP": 2, "STEP_UP->BLOCK": 1}
    assert out["names_used"] == ["tx.amount", "tx.is_new_payee"] and out["customers"] == 3
    assert admin.call("get", "/v1/bo/custom-rules")[1]["rules"] == []
    assert admin.call("post", "/v1/bo/custom-rules/test", {"expression": "tx.amout > 1", "points": 5})[0] == 400


def test_confirmed_outcomes_show_up_against_a_rule(api, admin, make_session):
    create(admin)
    s = make_session("genuine_new_payee", 9)
    run_session(api, s)
    assert api.post("/v1/feedback", {"session_id": s["evaluate"]["session_id"], "label": "FRAUD"}, auth=True)[0] == 201
    rule = admin.call("get", "/v1/bo/custom-rules")[1]["report"]["rules"]["big_new_payee"]
    assert rule["confirmed_fraud_hits"] == 1 and rule["confirmed_genuine_hits"] == 0


def test_replaying_history_keeps_what_a_live_rule_added(api, admin, bo_app, make_session):
    rule = create(admin, mode="live")[1]["rule"]
    user(bo_app, admin, "second.admin", "admin").call("post", f"/v1/bo/custom-rules/{rule['id']}/approve")
    decide(api, make_session)
    out = admin.call("post", "/v1/bo/rules/preview", {})[1]
    assert out["changed_total"] == 0 and out["after"]["STEP_UP"] == 1
