"""Consent wording with versions, consent records, and the signed configuration with its kill switches."""

import copy

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from fortguard import remote, signing
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


def get(bo_app, path):
    r = bo_app.test_client().get(path)
    return r.status_code, r.get_json()


def with_batches(session, change):
    """The same session with every batch changed by `change(payload)` and signed again."""
    def signed(batch):
        payload = copy.deepcopy({k: v for k, v in batch.items() if k != "signature"})
        change(payload)
        return session["device"].sign(payload)
    session["batches"] = [signed(b) for b in session["batches"]]
    return session


# --- Consent wording -----------------------------------------------------------------------------------

def test_the_app_gets_english_wording_out_of_the_box(bo_app):
    status, body = get(bo_app, "/v1/consent")
    assert status == 200 and set(body["groups"]) == {"behavioural", "location"}
    assert body["groups"]["behavioural"]["version"] == 1 and body["groups"]["behavioural"]["lang"] == "en"
    assert "never records what you type" in body["groups"]["behavioural"]["text"]


def test_publishing_raises_the_version_and_keeps_the_earlier_wording(bo_app, admin):
    text = "We measure how you type, touch and move the phone to keep fraudsters out. Never what you type."
    status, out = admin.call("post", "/v1/bo/consent", {"group": "behavioural", "lang": "en", "text": text})
    assert status == 201 and out["published"] == {"group": "behavioural", "lang": "en", "version": 2}
    assert get(bo_app, "/v1/consent")[1]["groups"]["behavioural"] == {"lang": "en", "version": 2, "text": text}
    entry = [t for t in admin.call("get", "/v1/bo/consent")[1]["texts"] if t["group"] == "behavioural" and t["lang"] == "en"][0]
    assert entry["current"]["version"] == 2 and entry["current"]["published_by"] == "admin"
    assert [e["version"] for e in entry["earlier"]] == [1]
    assert admin.call("post", "/v1/bo/consent", {"group": "behavioural", "lang": "en", "text": text})[0] == 409
    assert "consent_publish" in [a["action"] for a in admin.call("get", "/v1/bo/audit")[1]["audit"]]


def test_another_language_is_served_when_published_and_english_otherwise(bo_app, admin):
    urdu = "دھوکہ دہی سے بچاؤ کے لیے یہ ایپ دیکھتی ہے کہ آپ فون کیسے استعمال کرتے ہیں۔ یہ کبھی نہیں دیکھتی کہ آپ کیا لکھتے ہیں۔"
    assert admin.call("post", "/v1/bo/consent", {"group": "behavioural", "lang": "ur", "text": urdu})[0] == 201
    groups = get(bo_app, "/v1/consent?lang=ur")[1]["groups"]
    assert groups["behavioural"] == {"lang": "ur", "version": 1, "text": urdu}
    assert groups["location"]["lang"] == "en"                       # not translated yet: English is shown
    assert get(bo_app, "/v1/consent?lang=ur-PK")[1]["groups"]["behavioural"]["lang"] == "ur"
    assert get(bo_app, "/v1/consent?lang=';drop")[1]["groups"]["behavioural"]["lang"] == "en"


@pytest.mark.parametrize("bad", [{"group": "marketing", "lang": "en", "text": "x" * 40}, {"group": "location", "lang": "english", "text": "x" * 40},
                                 {"group": "location", "lang": "en", "text": "too short"}, {"group": "location", "lang": "en", "text": "x" * 2001},
                                 {"group": "location", "lang": "en", "text": "x" * 40, "extra": 1}])
def test_bad_wording_is_refused(admin, bad):
    assert admin.call("post", "/v1/bo/consent", bad)[0] == 400


def test_only_an_admin_publishes_wording(bo_app, admin):
    assert admin.call("post", "/v1/bo/users", {"username": "ana.lyst", "password": "long-enough-pw", "role": "analyst"})[0] == 201
    analyst = Portal(bo_app)
    analyst.login("ana.lyst", "long-enough-pw")
    assert analyst.call("get", "/v1/bo/consent")[0] == 200
    assert analyst.call("post", "/v1/bo/consent", {"group": "location", "lang": "en", "text": "x" * 40})[0] == 403


# --- Consent records -----------------------------------------------------------------------------------

def consent_of(payload, behavioural=True, location=None, texts=None):
    payload["consent"] = {"behavioral": behavioural}
    if location is not None:
        payload["consent"]["location"] = location
    if texts:
        payload["consent"]["texts"] = texts


def test_a_customers_answer_is_recorded_once_and_again_when_it_changes(api, admin, make_session):
    user = "usr_consent01"
    accepted = {"behavioural": {"lang": "en", "version": 1}, "location": {"lang": "en", "version": 1}}

    def run(seed, **kw):
        s = with_batches(make_session("genuine", seed), lambda p: (p.update(user_id=user), consent_of(p, **kw)))
        s["evaluate"]["user_id"] = user
        assert run_session(api, s)[0] == 200

    run(1, location=True, texts=accepted)
    run(2, location=True, texts=accepted)                           # nothing changed: no new record
    history = admin.call("get", f"/v1/bo/customers/{user}")[1]["consents"]
    assert [(h["group"], h["granted"], h["version"]) for h in history] == [("location", True, 1), ("behavioural", True, 1)]
    run(3, location=False, texts={"behavioural": {"lang": "en", "version": 2}})
    history = admin.call("get", f"/v1/bo/customers/{user}")[1]["consents"]
    assert [(h["group"], h["granted"], h["version"]) for h in history][:2] == [("location", False, None), ("behavioural", True, 2)]
    assert len(history) == 4 and history[0]["device_guid"]
    # Erasing the customer removes the records.
    assert admin.call("post", f"/v1/bo/customers/{user}/erase", {"confirm": user})[0] == 200
    assert admin.call("get", f"/v1/bo/customers/{user}")[0] == 404


@pytest.mark.parametrize("consent", [
    {"behavioral": True, "marketing": True}, {"behavioral": True, "location": "yes"},
    {"behavioral": True, "texts": {"marketing": {"lang": "en", "version": 1}}},
    {"behavioral": True, "texts": {"location": {"lang": "en"}}},
    {"behavioral": True, "texts": {"location": {"lang": "EN", "version": 1}}},
    {"behavioral": True, "texts": {"location": {"lang": "en", "version": 0}}},
    {"behavioral": True, "texts": {"location": {"lang": "en", "version": True}}},
])
def test_a_malformed_consent_block_is_refused(api, make_session, consent):
    s = with_batches(make_session("genuine", 4), lambda p: p.update(consent=consent))
    with pytest.raises(RuntimeError, match="telemetry rejected: 400"):
        run_session(api, s)


# --- Signed configuration ------------------------------------------------------------------------------

def verify(signed, public_key_b64):
    key = signing.load_public_key(public_key_b64)
    key.verify(signing.b64d(signed["signature"]), remote.CONFIG_CONTEXT + signing.canonical_bytes(signed["config"]), ec.ECDSA(hashes.SHA256()))


def test_the_configuration_is_signed_by_the_servers_key(bo_app):
    status, signed = get(bo_app, "/v1/config")
    key = get(bo_app, "/v1/config/key")[1]
    assert status == 200 and signed["key_sha256"] == key["key_sha256"] and key["algorithm"] == "ES256"
    assert signed["config"]["version"] == 1 and signed["config"]["collect"] == {k: True for k in remote.COLLECT_KINDS}
    verify(signed, key["public_key"])
    tampered = copy.deepcopy(signed)
    tampered["config"]["collect"]["touch"] = False
    with pytest.raises(InvalidSignature):
        verify(tampered, key["public_key"])


def test_a_telemetry_signature_is_not_a_config_signature(bo_app):
    signed = get(bo_app, "/v1/config")[1]
    key = signing.load_public_key(get(bo_app, "/v1/config/key")[1]["public_key"])
    with pytest.raises(InvalidSignature):
        key.verify(signing.b64d(signed["signature"]), signing.TELEMETRY_CONTEXT + signing.canonical_bytes(signed["config"]), ec.ECDSA(hashes.SHA256()))


def test_switching_a_kind_off_raises_the_version_and_is_audited(bo_app, admin):
    status, out = admin.call("put", "/v1/bo/config", {"collect": {"location": False}, "flush_interval_ms": 8000})
    assert status == 200 and out["config"]["version"] == 2
    assert out["config"]["collect"]["location"] is False and out["config"]["collect"]["touch"] is True
    signed = get(bo_app, "/v1/config")[1]
    assert signed["config"]["flush_interval_ms"] == 8000
    verify(signed, out["key"]["public_key"])
    assert admin.call("put", "/v1/bo/config", {"collect": {"location": False}})[1]["config"]["version"] == 2      # no change, no new version
    assert [a["action"] for a in admin.call("get", "/v1/bo/audit")[1]["audit"]].count("config_update") == 1


@pytest.mark.parametrize("bad", [{"collect": {"camera": False}}, {"collect": {"touch": "off"}}, {"collect": []},
                                 {"flush_interval_ms": 10}, {"flush_interval_ms": 2.5}, {"version": 99}])
def test_a_bad_configuration_is_refused(admin, bad):
    assert admin.call("put", "/v1/bo/config", bad)[0] == 400


def test_the_key_and_configuration_survive_a_restart(tmp_path, clock):
    path = str(tmp_path / "fortguard.db")
    first = create_app(clock=clock, admin_password=ADMIN_PW, dev_mode=True, db_path=path)
    p = Portal(first)
    p.login("admin", ADMIN_PW)
    p.call("put", "/v1/bo/config", {"collect": {"sensors": False}})
    key = get(first, "/v1/config/key")[1]
    again = create_app(clock=clock, admin_password=ADMIN_PW, dev_mode=True, db_path=path)
    assert get(again, "/v1/config/key")[1] == key
    signed = get(again, "/v1/config")[1]
    assert signed["config"]["version"] == 2 and signed["config"]["collect"]["sensors"] is False
    verify(signed, key["public_key"])


def test_the_server_drops_what_is_switched_off_even_if_an_app_still_sends_it(api, admin, bo_app, make_session):
    admin.call("put", "/v1/bo/config", {"collect": {"touch": False, "sensors": False, "location": False}})

    def add(p):
        p["environment"]["location"] = {"lat": 24.86, "lng": 67.0, "accuracy_m": 30, "fix_age_s": 5}
        p["sensor_data"]["light"] = [{"x": 300.0, "y": 0.0, "z": 0.0, "ts": p["timestamp_ms"]}]
    s = with_batches(make_session("genuine", 5), add)
    from fortguard.client import enroll_device
    assert enroll_device(api, s["device"], s["batches"][0]["timestamp_ms"] + 60_000)[0] == 201
    status, out = api.post("/v1/telemetry/stream", s["batches"][0])
    assert status == 202 and out["accepted"]["touch"] == 0 and out["config_version"] == 2
    assert set(out["switched_off"]) >= {"touch", "sensors", "location"}
    for batch in s["batches"][1:]:
        api.post("/v1/telemetry/stream", batch)
    status, body = api.post("/v1/risk/evaluate", s["evaluate"], auth=True)
    assert status == 200
    record = admin.call("get", "/v1/bo/decisions")[1]["decisions"][0]
    assert record["captured"]["touch"] == 0 and record["captured"].get("light", 0) == 0
    assert record["network"]["location"] is None
    assert record["captured"]["keys"] > 0                          # typing was left on and still arrives
