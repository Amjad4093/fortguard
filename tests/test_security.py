"""Telemetry signing, replay, tamper and privacy tests (BRD FR-SDK-001, NFR-003).

Batches are signed by the enrolled device's own key (ES256). The server holds only the public key.
"""

import copy

import pytest

from fortguard.client import run_session
from fortguard.signing import verify_payload
from fortguard.simdevice import SimDevice


def first_batch(enrolled):
    session = enrolled()
    return session, session["batches"][0]


def test_valid_signature_verifies_with_the_public_key_only(enrolled):
    session, batch = first_batch(enrolled)
    assert verify_payload(batch, session["device"].public_key)


def test_missing_signature_is_rejected(api, enrolled):
    _, batch = first_batch(enrolled)
    batch.pop("signature")
    status, body = api.post("/v1/telemetry/stream", batch)
    assert (status, body["error"]["code"]) == (401, "bad_signature")


def test_garbage_signature_is_rejected(api, enrolled):
    _, batch = first_batch(enrolled)
    for junk in ("", "AAAA", "not base64 !!", "x" * 5000):
        batch["signature"] = junk
        status, body = api.post("/v1/telemetry/stream", batch)
        assert (status, body["error"]["code"]) == (401, "bad_signature")


def test_altered_payload_is_rejected(api, enrolled):
    _, batch = first_batch(enrolled)
    batch["environment"]["is_rooted"] = True
    status, body = api.post("/v1/telemetry/stream", batch)
    assert (status, body["error"]["code"]) == (401, "bad_signature")


def test_altered_sensor_value_is_rejected(api, enrolled):
    _, batch = first_batch(enrolled)
    batch["sensor_data"]["accelerometer"][0]["x"] += 1
    status, body = api.post("/v1/telemetry/stream", batch)
    assert (status, body["error"]["code"]) == (401, "bad_signature")


def test_signature_from_another_devices_key_is_rejected(api, enrolled, make_session):
    session, batch = first_batch(enrolled)
    attacker = SimDevice("attacker")  # has a key, but it is not the enrolled one
    forged = attacker.sign(copy.deepcopy(batch))
    status, body = api.post("/v1/telemetry/stream", forged)
    assert (status, body["error"]["code"]) == (401, "bad_signature")


def test_unenrolled_device_is_rejected(api, make_session):
    batch = make_session()["batches"][0]
    status, body = api.post("/v1/telemetry/stream", batch)
    assert (status, body["error"]["code"]) == (401, "unknown_device")


def test_app_id_must_match_the_enrolled_app(api, enrolled, resign):
    session, batch = first_batch(enrolled)
    batch["app_id"] = "com.evil.clone"
    status, body = api.post("/v1/telemetry/stream", resign(batch, session))
    assert (status, body["error"]["code"]) == (403, "app_mismatch")


def test_replayed_batch_is_rejected(api, enrolled):
    _, batch = first_batch(enrolled)
    assert api.post("/v1/telemetry/stream", batch)[0] == 202
    status, body = api.post("/v1/telemetry/stream", batch)
    assert (status, body["error"]["code"]) == (409, "replay_detected")


def test_replay_does_not_double_count_events(api, app, enrolled):
    session, batch = first_batch(enrolled)
    api.post("/v1/telemetry/stream", batch)
    api.post("/v1/telemetry/stream", batch)
    stored = app.fortguard_store.get(batch["session_id"])
    assert len(stored.touch) == len(batch["touch_events"])


def test_stale_timestamp_is_rejected(api, enrolled, resign, clock):
    session, batch = first_batch(enrolled)
    batch["timestamp_ms"] = int(clock() * 1000) - 3_600_000
    status, body = api.post("/v1/telemetry/stream", resign(batch, session))
    assert (status, body["error"]["code"]) == (400, "stale_timestamp")


def test_future_timestamp_is_rejected(api, enrolled, resign, clock):
    session, batch = first_batch(enrolled)
    batch["timestamp_ms"] = int(clock() * 1000) + 3_600_000
    status, body = api.post("/v1/telemetry/stream", resign(batch, session))
    assert (status, body["error"]["code"]) == (400, "stale_timestamp")


def test_other_device_cannot_write_into_a_session(api, enrolled, make_session, clock, resign):
    """A second enrolled device, with a valid signature, still cannot join someone else's session."""
    from fortguard.client import enroll_device

    victim = enrolled()
    api.post("/v1/telemetry/stream", victim["batches"][0])
    intruder_device = SimDevice("intruder")
    assert enroll_device(api, intruder_device, int(clock() * 1000))[0] == 201
    batch = copy.deepcopy(victim["batches"][1])
    batch["device_guid"] = intruder_device.device_guid
    status, body = api.post("/v1/telemetry/stream", intruder_device.sign(batch))
    assert (status, body["error"]["code"]) == (409, "device_mismatch")


# --- No typed characters leave the device ---------------------------------------------------------


@pytest.mark.parametrize("extra_key", ["char", "text", "value", "key", "key_code", "content"])
def test_key_events_with_content_are_refused(api, enrolled, resign, extra_key):
    session, batch = first_batch(enrolled)
    batch["key_events"][0][extra_key] = "7"
    status, body = api.post("/v1/telemetry/stream", resign(batch, session))
    assert (status, body["error"]["code"]) == (422, "forbidden_field")


def test_ui_events_with_content_are_refused(api, enrolled, resign):
    session = enrolled()
    batch = session["batches"][1]
    batch["ui_events"][0]["text"] = "PK36EXMP00992201029381"
    status, body = api.post("/v1/telemetry/stream", resign(batch, session))
    assert (status, body["error"]["code"]) == (422, "forbidden_field")


def test_free_text_cannot_hide_in_the_field_name(api, enrolled, resign):
    session, batch = first_batch(enrolled)
    batch["key_events"][0]["field"] = "PK36EXMP00992201029381"
    status, body = api.post("/v1/telemetry/stream", resign(batch, session))
    assert (status, body["error"]["code"]) == (422, "forbidden_field")


def test_unknown_top_level_and_environment_fields_are_refused(api, enrolled, resign):
    session, batch = first_batch(enrolled)
    batch["clipboard"] = "secret"
    assert api.post("/v1/telemetry/stream", resign(batch, session))[1]["error"]["code"] == "unknown_field"
    session, batch = first_batch(enrolled)
    batch["environment"]["installed_apps"] = ["a", "b"]
    assert api.post("/v1/telemetry/stream", resign(batch, session))[1]["error"]["code"] == "unknown_field"


def test_generator_never_emits_content_fields(make_session):
    """The sample SDK itself must only produce the allowed event keys."""
    from fortguard.schema import KEY_KEYS, UI_KEYS

    for scenario in ("genuine", "coached_scam", "bot_scripted"):
        for batch in make_session(scenario)["batches"]:
            assert all(set(e) <= KEY_KEYS for e in batch["key_events"])
            assert all(set(e) <= UI_KEYS for e in batch["ui_events"])


def test_stored_session_holds_no_typed_content(api, app, make_session):
    session = make_session()
    run_session(api, session)
    stored = app.fortguard_store.get(session["session_id"])
    blob = repr(stored.keys) + repr(stored.ui)
    assert "PK36" not in blob


def test_no_consent_means_behavioral_data_is_dropped_server_side(api, app, make_session):
    session = make_session("no_consent")
    run_session(api, session)
    stored = app.fortguard_store.get(session["session_id"])
    assert stored.event_count() == 0
    assert stored.consent_behavioral is False
