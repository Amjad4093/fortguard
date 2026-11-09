"""Enrollment, attestation binding, revocation and the integrity signal."""

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from fortguard import config
from fortguard.app import create_app
from fortguard.attestation import AppAttestVerifier, PlayIntegrityVerifier, SimulatedAuthority
from fortguard.client import InProcessTransport, enroll_device, run_session
from fortguard.signing import b64e, public_key_to_b64
from fortguard.simdevice import SimDevice


def new_challenge(api):
    status, body = api.post("/v1/devices/challenge", {})
    assert status == 201
    return body["challenge"]


def enroll(api, device, clock, challenge=None, level="STRONG", **overrides):
    request = device.enrollment_request(challenge or new_challenge(api), int(clock() * 1000), level)
    request.update(overrides)
    return api.post("/v1/devices/enroll", request)


# --- Happy path and challenge rules ---------------------------------------------------------------


def test_enrollment_registers_the_device(api, app, clock):
    device = SimDevice("a")
    status, body = enroll(api, device, clock)
    assert status == 201
    assert body["device_guid"] == device.device_guid
    assert body["integrity_level"] == "STRONG"
    assert app.fortguard_registry.get(device.device_guid).status == "ACTIVE"


def test_challenge_is_single_use(api, clock):
    device, challenge = SimDevice("a"), new_challenge(api)
    assert enroll(api, device, clock, challenge)[0] == 201
    status, body = enroll(api, device, clock, challenge)
    assert (status, body["error"]["code"]) == (400, "invalid_challenge")


def test_unknown_challenge_is_refused(api, clock):
    status, body = enroll(api, SimDevice("a"), clock, challenge="never-issued-challenge")
    assert (status, body["error"]["code"]) == (400, "invalid_challenge")


def test_challenge_expires(api, clock):
    device, challenge = SimDevice("a"), new_challenge(api)
    clock.now += config.CHALLENGE_TTL_S + 1
    status, body = enroll(api, device, clock, challenge)
    assert (status, body["error"]["code"]) == (400, "invalid_challenge")


def test_a_failed_enrollment_still_burns_the_challenge(api, clock):
    device, challenge = SimDevice("a"), new_challenge(api)
    request = device.enrollment_request(challenge, int(clock() * 1000))
    request["attestation"] = "junk.junk"
    assert api.post("/v1/devices/enroll", request)[0] == 403
    status, body = enroll(api, device, clock, challenge)
    assert (status, body["error"]["code"]) == (400, "invalid_challenge")


def test_challenges_are_capped(clock, monkeypatch):
    monkeypatch.setattr(config, "MAX_CHALLENGES", 2)
    api = InProcessTransport(create_app(clock=clock))
    assert api.post("/v1/devices/challenge", {})[0] == 201
    assert api.post("/v1/devices/challenge", {})[0] == 201
    status, body = api.post("/v1/devices/challenge", {})
    assert (status, body["error"]["code"]) == (503, "busy")


# --- Attestation is bound to the key, challenge, device and app -----------------------------------


def test_attestation_for_another_key_is_refused(api, clock):
    honest, attacker = SimDevice("honest"), SimDevice("attacker")
    challenge = new_challenge(api)
    token = honest.enrollment_request(challenge, int(clock() * 1000))["attestation"]
    status, body = enroll(api, honest, clock, challenge, public_key=attacker.public_key_b64, attestation=token)
    assert (status, body["error"]["code"]) == (403, "attestation_failed")
    assert "key_sha256" in body["error"]["message"]


def test_attestation_for_another_challenge_is_refused(api, clock):
    device = SimDevice("a")
    old, fresh = new_challenge(api), new_challenge(api)
    token = device.enrollment_request(old, int(clock() * 1000))["attestation"]
    status, body = enroll(api, device, clock, fresh, attestation=token)
    assert (status, body["error"]["code"]) == (403, "attestation_failed")
    assert "challenge" in body["error"]["message"]


def test_attestation_for_another_device_id_is_refused(api, clock):
    a, b = SimDevice("a"), SimDevice("b")
    challenge = new_challenge(api)
    token = a.enrollment_request(challenge, int(clock() * 1000))["attestation"]
    status, body = enroll(api, a, clock, challenge, attestation=token, device_guid=b.device_guid)
    assert (status, body["error"]["code"]) == (403, "attestation_failed")


def test_attestation_for_another_app_is_refused(clock):
    # Both apps are allowed, so only the attestation binding can stop the swap.
    api = InProcessTransport(create_app(clock=clock, allowed_app_ids=["com.example.mobilebank", "com.example.other"]))
    status, body = enroll(api, SimDevice("a", app_id="com.example.mobilebank"), clock, app_id="com.example.other")
    assert (status, body["error"]["code"]) == (403, "attestation_failed")
    assert "app_id" in body["error"]["message"]


def test_forged_attestation_from_another_authority_is_refused(api, clock):
    forger = SimDevice("a", authority=SimulatedAuthority(seed=b"someone else"))
    status, body = enroll(api, forger, clock)
    assert (status, body["error"]["code"]) == (403, "attestation_failed")


def test_tampered_attestation_level_is_refused(api, clock):
    device = SimDevice("a")
    challenge = new_challenge(api)
    token = device.enrollment_request(challenge, int(clock() * 1000), level="BASIC")["attestation"]
    from fortguard.signing import b64d

    body_part, sig = token.split(".")
    upgraded = b64e(b64d(body_part).replace(b'"BASIC"', b'"STRONG"'))
    status, body = enroll(api, device, clock, challenge, attestation=upgraded + "." + sig)
    assert (status, body["error"]["code"]) == (403, "attestation_failed")


def test_stale_attestation_is_refused(api, clock):
    device = SimDevice("a")
    request = device.enrollment_request(new_challenge(api), int(clock() * 1000) - 3_600_000)
    status, body = api.post("/v1/devices/enroll", request)
    assert (status, body["error"]["code"]) == (403, "attestation_failed")
    assert "fresh" in body["error"]["message"]


@pytest.mark.parametrize("garbage", ["", "x", "a.b", "....", "!!!.???"])
def test_garbage_attestation_is_refused(api, clock, garbage):
    status, body = enroll(api, SimDevice("a"), clock, attestation=garbage or "x")
    assert status in (400, 403)


def test_app_not_on_the_allow_list_is_refused(api, clock):
    device = SimDevice("a", app_id="com.evil.clone")
    status, body = enroll(api, device, clock)
    assert (status, body["error"]["code"]) == (403, "app_not_allowed")


@pytest.mark.parametrize(
    "make_key",
    [
        lambda: "not-a-key",
        lambda: b64e(b"\x00" * 40),
        lambda: public_key_to_b64(ec.generate_private_key(ec.SECP384R1()).public_key()),  # wrong curve
    ],
)
def test_bad_public_keys_are_refused(api, clock, make_key):
    status, body = enroll(api, SimDevice("a"), clock, public_key=make_key())
    assert (status, body["error"]["code"]) == (400, "invalid_public_key")


def test_enroll_requires_every_field(api, clock):
    device = SimDevice("a")
    for name in ("device_guid", "app_id", "platform", "public_key", "challenge", "attestation"):
        request = device.enrollment_request(new_challenge(api), int(clock() * 1000))
        request.pop(name)
        status, body = api.post("/v1/devices/enroll", request)
        assert (status, body["error"]["code"]) == (400, "invalid_request"), name


def test_enroll_refuses_unknown_fields(api, clock):
    status, body = enroll(api, SimDevice("a"), clock, integrity="STRONG")  # the device cannot choose its level
    assert (status, body["error"]["code"]) == (400, "unknown_field")


def test_real_verifiers_are_not_configured_yet(clock):
    for verifier in (PlayIntegrityVerifier(), AppAttestVerifier()):
        api = InProcessTransport(create_app(clock=clock, verifier=verifier))
        status, body = enroll(api, SimDevice("a"), clock)
        assert (status, body["error"]["code"]) == (501, "attestation_not_configured")


# --- Revocation and re-enrollment -----------------------------------------------------------------


def test_revoked_device_cannot_send_telemetry(api, enrolled):
    session = enrolled()
    status, body = api.post(f"/v1/devices/{session['device'].device_guid}/revoke", {}, auth=True)
    assert (status, body["status"]) == (200, "REVOKED")
    status, body = api.post("/v1/telemetry/stream", session["batches"][0])
    assert (status, body["error"]["code"]) == (401, "device_revoked")


def test_revoked_device_cannot_enroll_again(api, enrolled, clock):
    session = enrolled()
    api.post(f"/v1/devices/{session['device'].device_guid}/revoke", {}, auth=True)
    status, body = enroll(api, session["device"], clock)
    assert (status, body["error"]["code"]) == (403, "device_revoked")


def test_revoke_needs_the_api_key(api, enrolled):
    session = enrolled()
    status, body = api.post(f"/v1/devices/{session['device'].device_guid}/revoke", {}, auth=False)
    assert (status, body["error"]["code"]) == (401, "unauthorized")


def test_revoke_unknown_device_is_a_defined_error(api):
    status, body = api.post("/v1/devices/dev_doesnotexist/revoke", {}, auth=True)
    assert (status, body["error"]["code"]) == (404, "unknown_device")


def test_re_enrolling_with_a_new_key_replaces_the_old_one(api, app, enrolled, clock, make_session):
    session = enrolled()
    old_batch = session["batches"][0]
    # Same device_guid, new key (for example after a reinstall).
    reinstalled = SimDevice("a-new-key")
    reinstalled.device_guid = session["device"].device_guid
    status, body = enroll(api, reinstalled, clock)
    assert (status, body["key_version"]) == (201, 2)
    # The old key's signature no longer works.
    assert api.post("/v1/telemetry/stream", old_batch)[1]["error"]["code"] == "bad_signature"


# --- The attestation level reaches the score --------------------------------------------------------


def evaluate(api, session, level):
    return run_session(api, session, level=level)[1]


def test_basic_integrity_adds_a_reason_and_points(api, make_session):
    body = evaluate(api, make_session("genuine"), "BASIC")
    assert "REASON_DEVICE_INTEGRITY_WEAK" in body["reason_codes"]
    assert body["risk_score"] == config.WEIGHTS["REASON_DEVICE_INTEGRITY_WEAK"]
    assert body["risk_level"] == "ALLOW"


@pytest.mark.parametrize("level", ["STRONG", "DEVICE"])
def test_stronger_integrity_adds_nothing(api, make_session, level):
    body = evaluate(api, make_session("genuine"), level)
    assert "REASON_DEVICE_INTEGRITY_WEAK" not in body["reason_codes"]
    assert body["risk_score"] == 0


def test_weak_integrity_adds_its_weight_on_top_of_other_signals(clock, make_session):
    scores = {}
    for level in ("STRONG", "BASIC"):
        api = InProcessTransport(create_app(clock=clock))  # fresh app each time, same session data
        scores[level] = evaluate(api, make_session("coached_scam"), level)["risk_score"]
    assert scores["BASIC"] == scores["STRONG"] + config.WEIGHTS["REASON_DEVICE_INTEGRITY_WEAK"]


def test_sdk_cannot_claim_its_own_integrity_level(api, enrolled, resign):
    session = enrolled()
    batch = session["batches"][0]
    batch["environment"]["integrity"] = "STRONG"
    status, body = api.post("/v1/telemetry/stream", resign(batch, session))
    assert (status, body["error"]["code"]) == (400, "unknown_field")
