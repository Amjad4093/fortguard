"""Velocity counters, the mule and trusted lists, and journeys, each checked through the API."""

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


@pytest.fixture
def pay(api, make_session):
    """Run one session and return the decision. Any evaluate field can be overridden."""
    seeds = iter(range(1000, 2000))

    def _pay(user=None, account=None, new=None, amount=None, device=None, enroll=True, scenario="genuine", event=None):
        s = make_session(scenario, next(seeds), device=device)
        ev = s["evaluate"]
        if user:
            ev["user_id"] = user
        if event:
            ev["event_type"] = event
            if event not in config.PAYMENT_EVENTS:
                ev.pop("transaction_details", None)
        tx = ev.get("transaction_details")
        if tx is not None:
            if account:
                tx["beneficiary_account"] = account
            if new is not None:
                tx["is_new_beneficiary"] = new
            if amount is not None:
                tx["amount"] = amount
        status, body = run_session(api, s, enroll=enroll)
        assert status == 200, body
        body["_device"] = s["device"]
        return body

    return _pay


# --- Velocity ------------------------------------------------------------------------------------------

def test_counters_count_the_request_being_decided(pay):
    first = pay(user="usr_velocity1", account="PK36EXMP0000000000000001", amount=1000)
    second = pay(user="usr_velocity1", account="PK36EXMP0000000000000002", amount=2500, new=True)
    assert first["velocity"] == {"payments_24h": 1, "amount_24h": 1000.0, "new_payees_24h": 0, "distinct_payees_7d": 1,
                                 "device_customers_7d": 1, "payee_customers_7d": 0}
    assert second["velocity"]["payments_24h"] == 2 and second["velocity"]["amount_24h"] == 3500.0
    assert second["velocity"]["new_payees_24h"] == 1 and second["velocity"]["distinct_payees_7d"] == 2


def test_another_customer_is_not_counted(pay):
    pay(user="usr_velocity2")
    assert pay(user="usr_velocity3")["velocity"]["payments_24h"] == 1


def test_many_payments_in_a_day_is_a_reason_and_wears_off(pay, clock, monkeypatch):
    monkeypatch.setattr(config, "VELOCITY_PAYMENTS_24H", 3)
    assert pay(user="usr_busy")["reason_codes"] == []
    assert pay(user="usr_busy")["reason_codes"] == []
    third = pay(user="usr_busy")
    assert third["reason_codes"] == ["REASON_VELOCITY_MANY_PAYMENTS"] and third["risk_level"] == "ALLOW"
    clock.now += 86_400 + 60
    later = pay(user="usr_busy")
    assert later["velocity"]["payments_24h"] == 1 and later["reason_codes"] == []


def test_several_new_payees_in_a_day(pay):
    for n in (1, 2):
        body = pay(user="usr_payees", account=f"PK36EXMP000000000000001{n}", new=True)
        assert "REASON_VELOCITY_MANY_NEW_PAYEES" not in body["reason_codes"]
    third = pay(user="usr_payees", account="PK36EXMP0000000000000013", new=True)
    assert third["velocity"]["new_payees_24h"] == 3
    assert "REASON_VELOCITY_MANY_NEW_PAYEES" in third["reason_codes"]
    # Paying one of them again adds no new payee.
    again = pay(user="usr_payees", account="PK36 EXMP 0000 0000 0000 0013", new=False)
    assert again["velocity"]["new_payees_24h"] == 3 and "REASON_VELOCITY_MANY_NEW_PAYEES" not in again["reason_codes"]


def test_one_phone_used_by_many_customers(pay):
    first = pay(user="usr_farm_a")
    device = first["_device"]
    second = pay(user="usr_farm_b", device=device, enroll=False)
    third = pay(user="usr_farm_c", device=device, enroll=False)
    assert second["velocity"]["device_customers_7d"] == 2 and second["reason_codes"] == []
    assert third["velocity"]["device_customers_7d"] == 3
    assert third["reason_codes"] == ["REASON_DEVICE_USED_BY_MANY_CUSTOMERS"]


def test_an_account_several_customers_add_in_a_week_looks_like_a_mule(pay, clock):
    account = "PK36EXMP0000000000007777"
    assert "REASON_PAYEE_PAID_BY_MANY_CUSTOMERS" not in pay(user="usr_v_a", account=account, new=True)["reason_codes"]
    assert "REASON_PAYEE_PAID_BY_MANY_CUSTOMERS" not in pay(user="usr_v_b", account=account, new=True)["reason_codes"]
    third = pay(user="usr_v_c", account=account, new=True)
    assert third["velocity"]["payee_customers_7d"] == 3
    assert "REASON_PAYEE_PAID_BY_MANY_CUSTOMERS" in third["reason_codes"]
    # A customer for whom it is an existing payee is not part of the pattern.
    regular = pay(user="usr_v_d", account=account, new=False)
    assert "REASON_PAYEE_PAID_BY_MANY_CUSTOMERS" not in regular["reason_codes"]
    clock.now += 8 * 86_400
    assert pay(user="usr_v_e", account=account, new=True)["velocity"]["payee_customers_7d"] == 1


def test_erasing_a_customer_removes_their_history(pay, admin):
    pay(user="usr_erase_me")
    pay(user="usr_erase_me")
    status, out = admin.call("post", "/v1/bo/customers/usr_erase_me/erase", {"confirm": "usr_erase_me"})
    assert status == 200, out
    assert pay(user="usr_erase_me")["velocity"]["payments_24h"] == 1


def test_history_is_purged_after_thirty_days(pay, admin, clock, bo_app):
    pay(user="usr_old")
    clock.now += 31 * 86_400
    assert admin.login("admin", ADMIN_PW)[0] == 200
    status, out = admin.call("post", "/v1/bo/maintenance/purge", {})
    assert status == 200 and out["deleted"]["velocity_history"] == 1, out


# --- Mule and trusted lists ----------------------------------------------------------------------------

def listed(admin, list_name, value, kind="account"):
    return admin.call("post", "/v1/bo/deny-list", {"kind": kind, "value": value, "reason": "from the industry feed", "list": list_name})


def test_a_suspected_mule_account_steps_up_alone_and_blocks_with_another_signal(pay, admin):
    account = "PK36EXMP0000000000004242"
    assert listed(admin, "mule", account)[0] == 201
    alone = pay(account=account)
    assert alone["reason_codes"] == ["REASON_SUSPECTED_MULE_ACCOUNT"] and alone["risk_level"] == "STEP_UP"
    assert alone["payee_lists"] == ["mule"] and alone["deny_list"] == []
    with_call = pay(account=account, scenario="coached_scam")
    assert with_call["risk_level"] == "BLOCK"


def test_a_trusted_payee_is_never_treated_as_new(pay, admin):
    account = "PK36EXMP0000000000005555"
    before = pay(account=account, new=True, scenario="genuine_new_payee")
    assert "REASON_NEW_BENEFICIARY" in before["reason_codes"]
    assert listed(admin, "allow", account)[0] == 201
    after = pay(account=account, new=True, scenario="genuine_new_payee")
    assert after["reason_codes"] == [] and after["payee_lists"] == ["allow"]


def test_only_accounts_go_on_the_mule_and_trusted_lists_and_on_one_list_at_a_time(admin):
    assert listed(admin, "mule", "usr_someone01", kind="customer")[0] == 400
    assert listed(admin, "allow", "203.0.113.5", kind="ip")[0] == 400
    assert listed(admin, "sanctions", "PK36EXMP0000000000006666")[0] == 400
    assert listed(admin, "mule", "PK36EXMP0000000000006666")[0] == 201
    status, body = listed(admin, "allow", "PK36EXMP0000000000006666")
    assert status == 409 and "suspected-mule list" in body["error"]["message"]
    entries = admin.call("get", "/v1/bo/deny-list")[1]
    assert entries["lists"] == ["deny", "mule", "allow"] and entries["entries"][0]["list"] == "mule"


def test_a_database_from_before_the_lists_is_upgraded(tmp_path, clock):
    import sqlite3
    path = str(tmp_path / "fortguard.db")
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE deny_list (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, value_hash TEXT NOT NULL, "
               "label TEXT NOT NULL, reason TEXT NOT NULL, added_by TEXT NOT NULL, created_ms INTEGER NOT NULL, expires_ms INTEGER, "
               "UNIQUE(kind, value_hash))")
    db.execute("INSERT INTO deny_list (kind, value_hash, label, reason, added_by, created_ms) VALUES ('ip','x','203.0.113.9','old','admin',1)")
    db.commit(); db.close()
    app = create_app(clock=clock, admin_password=ADMIN_PW, dev_mode=True, db_path=path)
    assert app.fortguard_backoffice.deny_entries()[0]["list"] == "deny"


# --- Journeys ------------------------------------------------------------------------------------------

def test_new_journeys_are_accepted_without_a_payee(pay):
    for event in ("PROFILE_CHANGE", "SIGN_UP", "DEVICE_ENROLLMENT"):
        body = pay(event=event)
        assert body["risk_level"] == "ALLOW" and body["reason_codes"] == [], (event, body)


def test_an_unknown_journey_is_refused(api, make_session):
    s = make_session("genuine", 5)
    s["evaluate"]["event_type"] = "WIRE_TO_MARS"
    assert run_session(api, s)[0] == 400


def test_a_profile_change_during_a_call_is_flagged_like_a_payment(pay):
    body = pay(event="PROFILE_CHANGE", scenario="coached_scam")
    assert "REASON_ACTIVE_CALL_DURING_PAYMENT" in body["reason_codes"]
    assert "REASON_NEW_BENEFICIARY" not in body["reason_codes"]


def test_a_journey_can_have_its_own_bands(pay, admin):
    status, rules = admin.call("put", "/v1/bo/rules", {"journey_bands": {"PROFILE_CHANGE": {"step_up_from": 150, "block_from": 900}}})
    assert status == 200 and rules["journey_bands"] == {"PROFILE_CHANGE": {"step_up_from": 150, "block_from": 900}}
    change = pay(event="PROFILE_CHANGE", scenario="coached_scam")
    payment = pay(scenario="genuine_new_payee")
    assert change["risk_level"] == "STEP_UP" and change["risk_score"] < 600
    assert payment["risk_score"] == 150 and payment["risk_level"] == "ALLOW"      # the default bands still apply to payments
    assert admin.call("put", "/v1/bo/rules", {"journey_bands": {}})[1]["journey_bands"] == {}
    assert pay(event="PROFILE_CHANGE", scenario="coached_scam")["risk_level"] == "ALLOW"


@pytest.mark.parametrize("bad", [{"MARS": {"step_up_from": 1, "block_from": 2}}, {"LOGIN": {"step_up_from": 900, "block_from": 600}},
                                 {"LOGIN": {"step_up_from": 100}}, {"LOGIN": {"step_up_from": 1.5, "block_from": 9}}, "LOGIN"])
def test_bad_journey_bands_are_refused(admin, bad):
    assert admin.call("put", "/v1/bo/rules", {"journey_bands": bad})[0] == 400


def test_journey_bands_survive_a_restart(tmp_path, clock):
    path = str(tmp_path / "fortguard.db")
    app = create_app(clock=clock, admin_password=ADMIN_PW, dev_mode=True, db_path=path)
    p = Portal(app)
    p.login("admin", ADMIN_PW)
    assert p.call("put", "/v1/bo/rules", {"journey_bands": {"SIGN_UP": {"step_up_from": 300, "block_from": 700}}})[0] == 200
    config.BANDS.pop("SIGN_UP")
    create_app(clock=clock, admin_password=ADMIN_PW, dev_mode=True, db_path=path)
    assert config.bands_for("SIGN_UP") == {"step_up_from": 300, "block_from": 700}
