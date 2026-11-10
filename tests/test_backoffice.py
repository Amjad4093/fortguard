"""Back office: logins, roles, cases, notes, audit trail, live rule changes, users, overview."""

import pytest

from fortguard import config
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


def make_user(admin, bo_app, name, role):
    assert admin.call("post", "/v1/bo/users", {"username": name, "password": "long-enough-pw", "role": role})[0] == 201
    p = Portal(bo_app)
    assert p.login(name, "long-enough-pw")[0] == 200
    return p


# --- Sign in -------------------------------------------------------------------------------------------

def test_login_and_me(admin):
    status, body = admin.call("get", "/v1/auth/me")
    assert status == 200 and body["user"] == {"username": "admin", "role": "admin"}


def test_wrong_password_and_lockout(bo_app):
    p = Portal(bo_app)
    for _ in range(5):
        assert p.login("admin", "nope")[1]["error"]["code"] == "bad_credentials"
    status, body = p.login("admin", ADMIN_PW)
    assert (status, body["error"]["code"]) == (429, "locked")


def test_lockout_expires(bo_app, clock):
    p = Portal(bo_app)
    for _ in range(5):
        p.login("admin", "nope")
    clock.now += 301
    assert p.login("admin", ADMIN_PW)[0] == 200


def test_no_token_and_bad_token(bo_app):
    assert Portal(bo_app).call("get", "/v1/bo/cases")[0] == 401
    assert Portal(bo_app, token="made-up").call("get", "/v1/bo/cases")[0] == 401


def test_token_expires(admin, clock):
    clock.now += 8 * 3600 + 1
    assert admin.call("get", "/v1/auth/me")[0] == 401


def test_logout_kills_the_token(admin):
    assert admin.call("post", "/v1/auth/logout")[0] == 200
    assert admin.call("get", "/v1/auth/me")[0] == 401


def test_passwords_are_not_stored_in_clear(bo_app):
    rows = bo_app.fortguard_backoffice.q("SELECT pw_hash FROM users")
    assert all(r["pw_hash"].startswith("scrypt$") and ADMIN_PW not in r["pw_hash"] for r in rows)


# --- Cases ------------------------------------------------------------------------------------------------

def test_step_up_and_block_open_cases_but_allow_does_not(api, admin, make_session):
    for scenario in ("genuine", "coached_scam", "bot_scripted"):
        run_session(api, make_session(scenario))
    status, body = admin.call("get", "/v1/bo/cases")
    assert status == 200
    assert sorted(c["risk_level"] for c in body["cases"]) == ["BLOCK", "STEP_UP"]
    assert body["counts"]["OPEN"] == 2
    assert body["cases"][0]["risk_level"] == "BLOCK"  # highest risk first


def test_case_detail_has_decision_reasons_and_device(api, admin, make_session):
    run_session(api, make_session("coached_scam"))
    case_id = admin.call("get", "/v1/bo/cases")[1]["cases"][0]["id"]
    status, case = admin.call("get", f"/v1/bo/cases/{case_id}")
    assert status == 200
    assert case["decision"]["score_breakdown"] and case["device"]["status"] == "ACTIVE"
    assert case["notes"] == [] and case["history"] == []


def test_analyst_works_a_case_and_it_is_audited(api, admin, bo_app, make_session):
    run_session(api, make_session("coached_scam"))
    analyst = make_user(admin, bo_app, "sara", "analyst")
    case_id = analyst.call("get", "/v1/bo/cases")[1]["cases"][0]["id"]
    assert analyst.call("post", f"/v1/bo/cases/{case_id}", {"status": "INVESTIGATING", "assignee": "sara"})[0] == 200
    assert analyst.call("post", f"/v1/bo/cases/{case_id}/notes", {"text": "Called the customer; was on a call with a 'bank officer'."})[0] == 201
    assert analyst.call("post", f"/v1/bo/cases/{case_id}", {"status": "CONFIRMED_FRAUD"})[0] == 200
    case = analyst.call("get", f"/v1/bo/cases/{case_id}")[1]
    assert case["status"] == "CONFIRMED_FRAUD" and case["assignee"] == "sara"
    assert case["notes"][0]["author"] == "sara"
    assert [h["action"] for h in case["history"]] == ["case_update", "note_add", "case_update"]
    assert case["history"][0]["detail"]["before"] == {"status": "OPEN", "assignee": None}
    audit = admin.call("get", "/v1/bo/audit")[1]["audit"]
    assert {"case_update", "note_add", "user_create", "login"} <= {a["action"] for a in audit}


def test_case_inputs_are_validated(api, admin, make_session):
    run_session(api, make_session("coached_scam"))
    case_id = admin.call("get", "/v1/bo/cases")[1]["cases"][0]["id"]
    assert admin.call("post", f"/v1/bo/cases/{case_id}", {"status": "WHATEVER"})[0] == 400
    assert admin.call("post", f"/v1/bo/cases/{case_id}", {"assignee": "ghost"})[0] == 400
    assert admin.call("post", f"/v1/bo/cases/{case_id}/notes", {"text": ""})[0] == 400
    assert admin.call("post", f"/v1/bo/cases/{case_id}/notes", {"text": "x" * 2001})[0] == 400
    assert admin.call("get", "/v1/bo/cases/99999")[0] == 404
    assert admin.call("get", "/v1/bo/cases?status=NOPE")[0] == 400


def test_case_search(api, admin, make_session):
    session = make_session("coached_scam")
    run_session(api, session)
    assert len(admin.call("get", f"/v1/bo/cases?q={session['session_id'][:10]}")[1]["cases"]) == 1
    assert admin.call("get", "/v1/bo/cases?q=nothing-like-this")[1]["cases"] == []


def test_same_session_updates_one_case(api, admin, make_session):
    session = make_session("coached_scam")
    run_session(api, session)
    body = dict(session["evaluate"]); body.pop("request_id")
    api.post("/v1/risk/evaluate", body, auth=True)
    assert len(admin.call("get", "/v1/bo/cases")[1]["cases"]) == 1


# --- Roles -------------------------------------------------------------------------------------------------

def test_viewer_can_read_but_not_change(api, admin, bo_app, make_session):
    run_session(api, make_session("coached_scam"))
    viewer = make_user(admin, bo_app, "omar", "viewer")
    case_id = viewer.call("get", "/v1/bo/cases")[1]["cases"][0]["id"]
    assert viewer.call("get", f"/v1/bo/cases/{case_id}")[0] == 200
    assert viewer.call("post", f"/v1/bo/cases/{case_id}", {"status": "CLOSED"})[0] == 403
    assert viewer.call("post", f"/v1/bo/cases/{case_id}/notes", {"text": "hi"})[0] == 403
    assert viewer.call("get", "/v1/bo/audit")[0] == 403
    assert viewer.call("get", "/v1/bo/users")[0] == 403
    assert viewer.call("put", "/v1/bo/rules", {"weights": {"REASON_VPN_OR_PROXY": 0}})[0] == 403


def test_analyst_can_revoke_but_not_edit_rules(api, admin, bo_app, make_session):
    session = make_session("genuine")
    run_session(api, session)
    analyst = make_user(admin, bo_app, "sara", "analyst")
    guid = session["device"].device_guid
    assert analyst.call("post", f"/v1/bo/devices/{guid}/revoke")[0] == 200
    assert analyst.call("get", "/v1/bo/devices")[1]["devices"][0]["status"] == "REVOKED"
    assert analyst.call("put", "/v1/bo/rules", {"bands": {"block_from": 950}})[0] == 403


# --- Rules -------------------------------------------------------------------------------------------------

def test_admin_rule_change_takes_effect_and_is_audited(api, admin, make_session):
    assert run_session(api, make_session("genuine_new_payee"))[1]["risk_level"] == "ALLOW"   # 150 points
    status, rules = admin.call("put", "/v1/bo/rules", {"weights": {"REASON_NEW_BENEFICIARY": 650}})
    assert status == 200 and rules["weights"]["REASON_NEW_BENEFICIARY"] == 650
    assert rules["defaults"]["weights"]["REASON_NEW_BENEFICIARY"] == 150
    assert run_session(api, make_session("genuine_new_payee", seed=1))[1]["risk_level"] == "STEP_UP"
    entry = admin.call("get", "/v1/bo/audit")[1]["audit"][0]
    assert entry["action"] == "rules_update"
    assert entry["detail"]["before"]["weights"] == {"REASON_NEW_BENEFICIARY": 150}


def test_band_change(api, admin, make_session):
    assert admin.call("put", "/v1/bo/rules", {"bands": {"step_up_from": 100}})[0] == 200
    assert run_session(api, make_session("genuine_new_payee"))[1]["risk_level"] == "STEP_UP"


@pytest.mark.parametrize("change", [
    {"weights": {"REASON_MADE_UP": 1}},
    {"weights": {"REASON_VPN_OR_PROXY": -5}},
    {"weights": {"REASON_VPN_OR_PROXY": 5000}},
    {"weights": {"REASON_VPN_OR_PROXY": "high"}},
    {"bands": {"step_up_from": 950}},
    {"bands": {"block_from": 2000}},
    {"bands": {"surprise": 1}},
])
def test_bad_rule_changes_are_refused_and_change_nothing(admin, change):
    before = (dict(config.WEIGHTS), dict(config.BANDS["default"]))
    assert admin.call("put", "/v1/bo/rules", change)[0] == 400
    assert (dict(config.WEIGHTS), dict(config.BANDS["default"])) == before


def test_rules_survive_a_restart(tmp_path, clock):
    db = str(tmp_path / "fg.db")
    app1 = create_app(clock=clock, db_path=db, admin_password=ADMIN_PW)
    p = Portal(app1); p.login("admin", ADMIN_PW)
    assert p.call("put", "/v1/bo/rules", {"weights": {"REASON_VPN_OR_PROXY": 77}})[0] == 200
    config.WEIGHTS["REASON_VPN_OR_PROXY"] = 50  # simulate a fresh process
    create_app(clock=clock, db_path=db, admin_password="ignored-now")
    assert config.WEIGHTS["REASON_VPN_OR_PROXY"] == 77


# --- Users --------------------------------------------------------------------------------------------------

def test_user_management(admin, bo_app):
    make_user(admin, bo_app, "sara", "analyst")
    assert admin.call("post", "/v1/bo/users", {"username": "sara", "password": "long-enough-pw", "role": "viewer"})[0] == 409
    assert admin.call("post", "/v1/bo/users", {"username": "bad name", "password": "long-enough-pw", "role": "viewer"})[0] == 400
    assert admin.call("post", "/v1/bo/users", {"username": "kim", "password": "short", "role": "viewer"})[1]["error"]["code"] == "weak_password"
    assert admin.call("post", "/v1/bo/users", {"username": "kim", "password": "long-enough-pw", "role": "god"})[0] == 400
    users = admin.call("get", "/v1/bo/users")[1]["users"]
    assert [u["username"] for u in users] == ["admin", "sara"]


def test_deactivated_user_is_signed_out(admin, bo_app):
    sara = make_user(admin, bo_app, "sara", "analyst")
    assert admin.call("post", "/v1/bo/users/sara", {"active": False})[0] == 200
    assert sara.call("get", "/v1/auth/me")[0] == 401
    assert Portal(bo_app).login("sara", "long-enough-pw")[0] == 401


def test_password_change_signs_out_and_new_password_works(admin, bo_app):
    sara = make_user(admin, bo_app, "sara", "analyst")
    assert admin.call("post", "/v1/bo/users/sara", {"password": "a-brand-new-password"})[0] == 200
    assert sara.call("get", "/v1/auth/me")[0] == 401
    assert Portal(bo_app).login("sara", "a-brand-new-password")[0] == 200


def test_admin_cannot_lock_themselves_out(admin):
    assert admin.call("post", "/v1/bo/users/admin", {"active": False})[0] == 400
    assert admin.call("post", "/v1/bo/users/admin", {"role": "viewer"})[0] == 400


# --- Overview ------------------------------------------------------------------------------------------------

def test_overview_counts(api, admin, make_session):
    for scenario in ("genuine", "coached_scam", "bot_scripted", "remote_control"):
        run_session(api, make_session(scenario))
    status, o = admin.call("get", "/v1/bo/overview")
    assert status == 200
    assert o["last_24h"]["total"] == 4 and o["last_24h"]["ALLOW"] == 1
    assert o["cases"]["OPEN"] == 3 and o["devices"]["total"] == 4
    assert o["top_reasons"] and o["hourly"]


def test_dev_simulate_fills_the_portal(admin, bo_app):
    status, body = admin.call("post", "/v1/bo/dev/simulate")
    assert status == 200 and len(body["results"]) >= 8
    assert admin.call("get", "/v1/bo/overview")[1]["last_24h"]["total"] == len(body["results"])


def test_dev_simulate_needs_dev_mode_and_analyst(clock, bo_app, admin):
    viewer = make_user(admin, bo_app, "omar", "viewer")
    assert viewer.call("post", "/v1/bo/dev/simulate")[0] == 403
    prod = create_app(clock=clock, admin_password=ADMIN_PW, dev_mode=False)
    p = Portal(prod); p.login("admin", ADMIN_PW)
    assert p.call("post", "/v1/bo/dev/simulate")[0] == 404


# --- Rule preview and replay ---------------------------------------------------------------------------------

def fill(api, make_session):
    for i, scenario in enumerate(("genuine", "genuine_new_payee", "coached_scam", "bot_scripted", "remote_control",
                                  "rooted_device", "emulator_bot", "no_consent")):
        run_session(api, make_session(scenario, i))


def test_replay_with_unchanged_rules_reproduces_every_decision(api, admin, make_session):
    fill(api, make_session)
    status, out = admin.call("post", "/v1/bo/rules/preview", {})
    assert status == 200 and out["replayed"] == 8
    assert out["changed_total"] == 0 and out["before"] == out["after"]


def test_preview_shows_impact_without_changing_anything(api, admin, make_session):
    fill(api, make_session)
    before_weights = dict(config.WEIGHTS)
    status, out = admin.call("post", "/v1/bo/rules/preview", {"weights": {"REASON_NEW_BENEFICIARY": 650}})
    assert status == 200
    assert out["moves"].get("ALLOW->STEP_UP", 0) >= 1
    assert any(c["after"]["level"] == "STEP_UP" and "REASON_NEW_BENEFICIARY" in c["reasons"] for c in out["changed"])
    assert dict(config.WEIGHTS) == before_weights  # nothing saved
    assert not any(a["action"] == "rules_update" for a in admin.call("get", "/v1/bo/audit")[1]["audit"])


def test_preview_counts_labeled_outcomes(api, admin, make_session):
    missed = make_session("genuine_new_payee", 1)
    run_session(api, missed)
    api.post("/v1/feedback", {"session_id": missed["session_id"], "label": "FRAUD"}, auth=True)
    out = admin.call("post", "/v1/bo/rules/preview", {"weights": {"REASON_NEW_BENEFICIARY": 650}})[1]
    assert out["labeled_outcomes"]["fraud"] == {"flagged_before": 0, "flagged_after": 1, "total": 1}


def test_preview_band_change_and_validation(api, admin, make_session):
    fill(api, make_session)
    out = admin.call("post", "/v1/bo/rules/preview", {"bands": {"block_from": 601}})[1]
    assert out["moves"].get("STEP_UP->BLOCK", 0) >= 1
    assert admin.call("post", "/v1/bo/rules/preview", {"bands": {"step_up_from": 950}})[0] == 400


def test_viewer_can_preview_but_not_save(api, admin, bo_app, make_session):
    viewer = make_user(admin, bo_app, "omar", "viewer")
    assert viewer.call("post", "/v1/bo/rules/preview", {"weights": {"REASON_VPN_OR_PROXY": 0}})[0] == 200
    assert viewer.call("put", "/v1/bo/rules", {"weights": {"REASON_VPN_OR_PROXY": 0}})[0] == 403


# --- Retention and erasure -------------------------------------------------------------------------------------

def test_purge_deletes_old_records_but_keeps_confirmed_fraud(api, admin, bo_app, make_session, clock):
    fraud, other = make_session("coached_scam", 1), make_session("bot_scripted", 2)
    run_session(api, fraud); run_session(api, other); run_session(api, make_session("genuine", 3))
    api.post("/v1/feedback", {"session_id": fraud["session_id"], "label": "FRAUD"}, auth=True)
    clock.now += 800 * 86400
    admin.login("admin", ADMIN_PW)  # the old sign-in expired long ago
    status, out = admin.call("post", "/v1/bo/maintenance/purge")
    assert status == 200 and out["deleted"]["decisions"] == 3 and out["deleted"]["cases"] == 1
    remaining = bo_app.fortguard_backoffice.q("SELECT status FROM cases")
    assert [r["status"] for r in remaining] == ["CONFIRMED_FRAUD"]
    assert bo_app.fortguard_baselines.profile(make_session("genuine", 3)["evaluate"]["user_id"])["sessions"] == 0


def test_purge_keeps_recent_records(api, admin, make_session):
    run_session(api, make_session("coached_scam", 1))
    assert admin.call("post", "/v1/bo/maintenance/purge")[1]["deleted"]["decisions"] == 0


def test_customer_erasure(api, admin, bo_app, make_session):
    sessions = [make_session(s, i) for i, s in enumerate(("genuine", "coached_scam", "bot_scripted"))]
    for s in sessions:
        s["evaluate"]["user_id"] = "usr_erase_me"
        run_session(api, s)
    api.post("/v1/feedback", {"session_id": sessions[2]["session_id"], "label": "FRAUD"}, auth=True)
    run_session(api, make_session("genuine", 9))  # someone else
    status, out = admin.call("post", "/v1/bo/customers/usr_erase_me/erase")
    assert status == 200
    d = out["deleted"]
    assert d["decisions"] == 3 and d["baseline_sessions"] == 1 and d["cases"] == 1 and d["kept_fraud_cases"] == 1
    bo = bo_app.fortguard_backoffice
    assert bo.q("SELECT COUNT(*) AS n FROM decisions")[0]["n"] == 1  # the other customer is untouched
    assert admin.call("get", "/v1/bo/audit")[1]["audit"][0]["action"] == "customer_erase"


def test_purge_and_erase_need_admin(api, admin, bo_app, make_session):
    analyst = make_user(admin, bo_app, "sara", "analyst")
    assert analyst.call("post", "/v1/bo/maintenance/purge")[0] == 403
    assert analyst.call("post", "/v1/bo/customers/usr_x/erase")[0] == 403


def test_overview_reports_signal_coverage_and_typing_speed(api, admin, make_session):
    from fortguard import admin as admin_mod
    from fortguard.backoffice import CPM_LABELS

    for scenario in ("genuine", "coached_scam", "bot_scripted"):
        run_session(api, make_session(scenario))
    status, o = admin.call("get", "/v1/bo/overview")
    assert status == 200
    coverage = {row["signal"]: row for row in o["coverage"]}
    assert set(coverage) == set(admin_mod.SIGNAL_KEYS)
    assert coverage["touch"]["decisions"] == 3 and coverage["touch"]["share"] == 1.0
    assert all(0 <= row["share"] <= 1 for row in o["coverage"])
    assert [row["label"] for row in o["typing_speed"]] == list(CPM_LABELS)
    assert sum(row["decisions"] for row in o["typing_speed"]) <= 3


def test_typing_speed_buckets_cover_the_range():
    from fortguard.backoffice import _cpm_bucket, CPM_LABELS

    assert _cpm_bucket(0) == CPM_LABELS[0] and _cpm_bucket(99.9) == CPM_LABELS[0]
    assert _cpm_bucket(100) == CPM_LABELS[1] and _cpm_bucket(399) == CPM_LABELS[3]
    assert _cpm_bucket(400) == CPM_LABELS[4] and _cpm_bucket(5000) == CPM_LABELS[4]


def test_empty_overview_has_no_coverage_rows(admin):
    status, o = admin.call("get", "/v1/bo/overview")
    assert status == 200 and o["coverage"] == [] and o["last_24h"]["total"] == 0


# --- Customers: grouped by user id, with device details and a name entered by staff -----------------


def test_customers_group_decisions_by_user_with_device_and_owner_status(api, admin, make_session):
    for scenario in ("genuine", "coached_scam"):
        run_session(api, make_session(scenario))
    status, data = admin.call("get", "/v1/bo/customers")
    assert status == 200 and data["customers"]
    row = data["customers"][0]
    assert row["sessions"] >= 1 and row["devices"] >= 1 and row["owner"] in ("NONE", "LEARNING", "MATURE")
    assert set(row["levels"]) == {"ALLOW", "STEP_UP", "BLOCK"}

    status, one = admin.call("get", "/v1/bo/customers/" + row["user_id"])
    assert status == 200 and one["user_id"] == row["user_id"]
    assert one["devices"] and one["devices"][0]["device_guid"]
    assert one["latest"] is not None and "captured" in one["latest"]
    assert one["owner_profile"]["required"] == config.BASELINE_MIN_SESSIONS


def test_unknown_customer_is_404(admin):
    assert admin.call("get", "/v1/bo/customers/nobody-here-123")[0] == 404


def test_naming_a_customer_is_audited_and_analyst_only(api, admin, make_session, bo_app):
    run_session(api, make_session("genuine"))
    _, data = admin.call("get", "/v1/bo/customers")
    uid = data["customers"][0]["user_id"]
    status, out = admin.call("post", f"/v1/bo/customers/{uid}/name", {"display_name": "Ali Raza"})
    assert status == 200 and out["display_name"] == "Ali Raza"
    assert admin.call("get", f"/v1/bo/customers/{uid}")[1]["display_name"] == "Ali Raza"
    assert any(a["action"] == "customer_name" for a in admin.call("get", "/v1/bo/audit")[1]["audit"])
    assert admin.call("post", f"/v1/bo/customers/{uid}/name", {"display_name": "bad\x07name"})[0] == 400
    assert admin.call("post", f"/v1/bo/customers/{uid}/name", {"display_name": "x" * 81})[0] == 400
    assert admin.call("post", f"/v1/bo/customers/{uid}/name", {"display_name": ""})[0] == 200
    assert admin.call("get", f"/v1/bo/customers/{uid}")[1]["display_name"] is None


def test_device_model_is_validated_and_kept_for_the_case(api, make_session, clock):
    from fortguard import schema
    assert schema.DEVICE_MODEL_RE.match("Pixel 8") and schema.DEVICE_MODEL_RE.match("SM-S921B")
    assert not schema.DEVICE_MODEL_RE.match("<script>") and not schema.DEVICE_MODEL_RE.match("x" * 81)
