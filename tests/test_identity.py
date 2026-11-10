"""Customer identity and time in the app: a batch may name the customer and the name typed in the app.
Usage is recorded per customer, and the back office reports maturity and sensor coverage from it."""

import pytest

from fortguard import config
from fortguard.app import create_app
from fortguard.backoffice import _coverage, _maturity
from fortguard.client import InProcessTransport, enroll_device


@pytest.fixture
def app(clock):
    return create_app(clock=clock)


@pytest.fixture
def api(app):
    return InProcessTransport(app)


def enroll(api, session, clock):
    status, body = enroll_device(api, session["device"], int(clock() * 1000), "STRONG")
    assert status == 201, body


def with_identity(batch, device, user_id="usr_cust00001", name=None):
    payload = {k: v for k, v in batch.items() if k != "signature"}
    payload["user_id"] = user_id
    if name is not None:
        payload["customer_name"] = name
    return device.sign(payload)


def test_batches_record_time_in_app_and_the_customer_name(api, app, make_session, clock):
    s = make_session("genuine")
    enroll(api, s, clock)
    for batch in s["batches"]:
        status, body = api.post("/v1/telemetry/stream", with_identity(batch, s["device"], name="Ayesha Khan"))
        assert status == 202, body
    bo = app.fortguard_backoffice
    usage = bo.q("SELECT batches, active_ms FROM usage WHERE user_id=?", ("usr_cust00001",))[0]
    assert usage["batches"] == len(s["batches"])
    assert usage["active_ms"] > 0
    assert bo.q("SELECT display_name FROM customers WHERE user_id=?", ("usr_cust00001",))[0]["display_name"] == "Ayesha Khan"


def test_the_first_name_is_kept_and_time_in_app_only_adds_up(api, app, make_session, clock):
    s = make_session("genuine")
    enroll(api, s, clock)
    api.post("/v1/telemetry/stream", with_identity(s["batches"][0], s["device"], name="Ayesha Khan"))
    api.post("/v1/telemetry/stream", with_identity(s["batches"][1], s["device"], name="Someone Else"))
    bo = app.fortguard_backoffice
    assert bo.q("SELECT display_name FROM customers WHERE user_id=?", ("usr_cust00001",))[0]["display_name"] == "Ayesha Khan"
    assert bo.q("SELECT batches FROM usage WHERE user_id=?", ("usr_cust00001",))[0]["batches"] == 2


@pytest.mark.parametrize("name", ["", "   ", "x" * 81, "Bad\nname"])
def test_a_bad_customer_name_is_refused(api, make_session, clock, name):
    s = make_session("genuine")
    enroll(api, s, clock)
    status, body = api.post("/v1/telemetry/stream", with_identity(s["batches"][0], s["device"], name=name))
    assert status == 400 and body["error"]["code"] == "invalid_request"


def test_a_bad_customer_id_is_refused(api, make_session, clock):
    s = make_session("genuine")
    enroll(api, s, clock)
    payload = {k: v for k, v in s["batches"][0].items() if k != "signature"}
    payload["user_id"] = "usr with spaces"
    status, body = api.post("/v1/telemetry/stream", s["device"].sign(payload))
    assert status == 400 and body["error"]["code"] == "invalid_request"


def test_a_batch_without_identity_is_still_accepted(api, make_session, clock):
    s = make_session("genuine")
    enroll(api, s, clock)
    status, _ = api.post("/v1/telemetry/stream", s["device"].sign(
        {k: v for k, v in s["batches"][0].items() if k != "signature"}))
    assert status == 202


def test_maturity_is_the_share_of_the_profile_built_so_far():
    need = config.BASELINE_MIN_SESSIONS
    assert _maturity({"sessions": 0, "required": need}) == 0.0
    assert _maturity({"sessions": need // 2, "required": need}) == 0.5
    assert _maturity({"sessions": need * 3, "required": need}) == 1.0


def test_coverage_counts_the_sensors_that_reported_in_the_newest_session():
    latest = {"captured": {"accelerometer": 120, "gyroscope": 80, "light": 0, "magnetometer": 4}}
    cov = _coverage(latest)
    assert cov["reporting"] == 3 and cov["of"] == len(config.SENSOR_NAMES)
    assert set(cov["names"]) == {"accelerometer", "gyroscope", "magnetometer"}
    assert _coverage(None) == {"reporting": 0, "of": len(config.SENSOR_NAMES), "names": []}
