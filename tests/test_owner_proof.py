"""Owner enrolment: a batch can carry a proof made by the owner's own key. The device keeps one owner key,
and a session with a valid proof teaches the owner profile even when the decision is a step-up."""

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from fortguard import config
from fortguard.app import create_app
from fortguard.client import InProcessTransport, enroll_device
from fortguard.signing import b64e, key_sha256, owner_signed_bytes, public_key_to_b64


def owner_key():
    return ec.generate_private_key(ec.SECP256R1())


def owner_proof(payload, owner):
    body = {k: v for k, v in payload.items() if k not in ("signature", "owner_proof")}
    signature = owner.sign(owner_signed_bytes(body), ec.ECDSA(hashes.SHA256()))
    return {"public_key": public_key_to_b64(owner.public_key()), "signature": b64e(signature)}


def with_owner_proof(batch, owner, device):
    payload = {k: v for k, v in batch.items() if k != "signature"}
    payload["owner_proof"] = owner_proof(payload, owner)
    return device.sign(payload)


@pytest.fixture
def app(clock):
    return create_app(clock=clock)


@pytest.fixture
def api(app):
    return InProcessTransport(app)


def enroll(api, session, clock):
    status, body = enroll_device(api, session["device"], int(clock() * 1000), "STRONG")
    assert status == 201, body


def test_valid_owner_proof_is_accepted_and_binds_the_owner_key(api, app, make_session, clock):
    s = make_session("genuine")
    enroll(api, s, clock)
    owner = owner_key()
    for batch in s["batches"]:
        status, body = api.post("/v1/telemetry/stream", with_owner_proof(batch, owner, s["device"]))
        assert status == 202, body
    device = app.fortguard_registry.get(s["batches"][0]["device_guid"])
    assert device.owner_key_sha256 == key_sha256(owner.public_key())


def test_tampered_batch_fails_the_owner_proof(api, make_session, clock):
    s = make_session("genuine")
    enroll(api, s, clock)
    owner = owner_key()
    batch = s["batches"][0]
    payload = {k: v for k, v in batch.items() if k != "signature"}
    proof = owner_proof(payload, owner)  # proof for the original batch ...
    payload["seq"] = payload["seq"] + 1  # ... then the batch is changed
    payload["owner_proof"] = proof
    status, body = api.post("/v1/telemetry/stream", s["device"].sign(payload))
    assert status == 401 and body["error"]["code"] == "bad_owner_proof"


def test_a_second_owner_key_cannot_take_over_the_device(api, make_session, clock):
    first = make_session("genuine", seed=0)
    enroll(api, first, clock)
    assert api.post("/v1/telemetry/stream", with_owner_proof(first["batches"][0], owner_key(), first["device"]))[0] == 202
    second = make_session("genuine", seed=1, device=first["device"])
    status, body = api.post("/v1/telemetry/stream", with_owner_proof(second["batches"][0], owner_key(), first["device"]))
    assert status == 403 and body["error"]["code"] == "owner_key_mismatch"


def test_owner_proved_step_up_session_still_teaches_the_profile(api, app, make_session, clock):
    owner = owner_key()
    proved = make_session("coached_scam", seed=3)
    enroll(api, proved, clock)
    for batch in proved["batches"]:
        assert api.post("/v1/telemetry/stream", with_owner_proof(batch, owner, proved["device"]))[0] == 202
    status, decision = api.post("/v1/risk/evaluate", proved["evaluate"], auth=True)
    assert status == 200 and decision["risk_level"] != "ALLOW"
    user = proved["evaluate"]["user_id"]
    assert app.fortguard_baselines.profile(user)["sessions"] == 1

    plain = make_session("coached_scam", seed=4)
    enroll(api, plain, clock)
    for batch in plain["batches"]:
        assert api.post("/v1/telemetry/stream", batch)[0] == 202
    assert api.post("/v1/risk/evaluate", plain["evaluate"], auth=True)[1]["risk_level"] != "ALLOW"
    assert app.fortguard_baselines.profile(plain["evaluate"]["user_id"])["sessions"] == 0


def test_owner_proof_with_extra_fields_is_refused(api, make_session, clock):
    s = make_session("genuine")
    enroll(api, s, clock)
    payload = {k: v for k, v in s["batches"][0].items() if k != "signature"}
    payload["owner_proof"] = dict(owner_proof(payload, owner_key()), extra="x")
    status, _ = api.post("/v1/telemetry/stream", s["device"].sign(payload))
    assert status == 400
