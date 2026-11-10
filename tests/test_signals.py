"""Every on-device signal, end to end: the app reports a flag, the server records it, and scoring names it.
Network facts (IP, approximate location) are checked as the server records them."""

import copy

import pytest

from fortguard import config
from fortguard.client import enroll_device, run_session
from fortguard.store import Session, _note_location

# Environment flag -> the reason the server gives when the flag is set on a payment.
FLAG_REASON = {
    "is_rooted": "REASON_DEVICE_ROOTED_OR_JAILBROKEN",
    "is_emulator": "REASON_EMULATOR_DETECTED",
    "has_hooking_framework": "REASON_HOOKING_FRAMEWORK_DETECTED",
    "active_remote_software": "REASON_REMOTE_ACCESS_TOOL_ACTIVE",
    "vpn": "REASON_VPN_OR_PROXY",
    "mock_location": "REASON_LOCATION_SPOOFING_SUSPECTED",
    "screen_sharing": "REASON_SCREEN_SHARING_ACTIVE",  # sensitive: counts on a payment
    "active_call": "REASON_ACTIVE_CALL_DURING_PAYMENT",
    "cellular_call": "REASON_ACTIVE_CALL_DURING_PAYMENT",
}


def reasons_of(body):
    return list(body.get("reason_codes", []))


def resign(batch, device, change):
    # Deep copy: batches in one session share their environment dict, and a shallow copy would change them all.
    payload = copy.deepcopy({k: v for k, v in batch.items() if k != "signature"})
    change(payload)
    return device.sign(payload)


@pytest.mark.parametrize("flag", sorted(FLAG_REASON))
def test_each_flag_reaches_the_decision_as_its_reason(api, make_session, flag):
    s = make_session("genuine", 1)
    s["batches"] = [resign(b, s["device"], lambda p: p["environment"].update({flag: True})) for b in s["batches"]]
    status, body = run_session(api, s)
    assert status == 200, body
    assert FLAG_REASON[flag] in reasons_of(body), body


def test_a_clean_phone_gets_none_of_the_environment_reasons(api, make_session):
    s = make_session("genuine", 2)
    status, body = run_session(api, s)
    assert status == 200
    assert not set(FLAG_REASON.values()) & set(reasons_of(body)), body


def test_a_phone_that_jumps_across_the_world_is_flagged(api, make_session):
    s = make_session("genuine", 3)
    paris, karachi = {"lat": 48.85, "lng": 2.35, "accuracy_m": 20, "fix_age_s": 0}, {"lat": 24.86, "lng": 67.0, "accuracy_m": 20, "fix_age_s": 0}
    s["batches"][0] = resign(s["batches"][0], s["device"], lambda p: p["environment"].update(location=paris))
    s["batches"][1] = resign(s["batches"][1], s["device"], lambda p: p["environment"].update(location=karachi))
    status, body = run_session(api, s)
    assert status == 200
    assert "REASON_LOCATION_JUMP_DETECTED" in reasons_of(body), body


def fresh_session():
    return Session("s_test", "dev_test", 0.0, 0.0)


def test_stationary_phone_is_not_a_jump():
    s = fresh_session()
    here = {"lat": 24.86, "lng": 67.0, "accuracy_m": 15, "fix_age_s": 0}
    _note_location(s, here, 1_000_000)
    _note_location(s, here, 1_005_000)
    assert s.location_jump is False


def test_a_normal_drive_is_not_a_jump():
    s = fresh_session()
    _note_location(s, {"lat": 24.86, "lng": 67.00, "fix_age_s": 0}, 1_000_000)
    _note_location(s, {"lat": 24.90, "lng": 67.05, "fix_age_s": 0}, 1_000_000 + 10 * 60_000)  # about 8 km in 10 min
    assert s.location_jump is False


def test_a_jump_is_sticky_for_the_session():
    s = fresh_session()
    _note_location(s, {"lat": 48.85, "lng": 2.35, "fix_age_s": 0}, 1_000_000)
    _note_location(s, {"lat": 24.86, "lng": 67.0, "fix_age_s": 0}, 1_005_000)
    _note_location(s, {"lat": 24.86, "lng": 67.0, "fix_age_s": 0}, 1_010_000)
    assert s.location_jump is True


def test_a_stale_fix_is_compared_at_the_time_it_was_taken():
    # The second batch arrives 5 s later, but its location is an hour old, so the phone did not move far in 5 s.
    s = fresh_session()
    _note_location(s, {"lat": 48.85, "lng": 2.35, "fix_age_s": 0}, 1_000_000)
    _note_location(s, {"lat": 24.86, "lng": 67.0, "fix_age_s": 3600}, 1_005_000)
    assert s.location_jump is False
    assert s.location["fix_ts_ms"] == 1_005_000 - 3_600_000


def test_the_threshold_is_the_documented_one():
    assert config.LOCATION_MAX_KMH == 900 and config.LOCATION_JUMP_MIN_KM == 50


@pytest.mark.parametrize("bad", [
    {"lat": 91, "lng": 0}, {"lat": 0, "lng": 181}, {"lat": 0}, {"lat": 0, "lng": 0, "speed": 3},
    {"lat": "0", "lng": 0}, {"lat": True, "lng": 0},
])
def test_malformed_location_is_refused(api, make_session, clock, bad):
    s = make_session("genuine", 4)
    enroll_device(api, s["device"], s["batches"][0]["timestamp_ms"] + 60_000, "STRONG")
    batch = resign(s["batches"][0], s["device"], lambda p: p["environment"].update(location=bad))
    status, body = api.post("/v1/telemetry/stream", batch)
    assert status == 400 and body["error"]["code"] == "invalid_request", body


def test_ip_changes_within_a_session_are_counted():
    from fortguard.store import SessionStore, _note_ip
    s = fresh_session()
    _note_ip(s, "10.0.0.1")
    _note_ip(s, "10.0.0.1")
    assert s.ip_changes == 0
    _note_ip(s, "10.0.0.2")
    assert s.ip == "10.0.0.2" and s.ip_changes == 1


def test_the_decision_record_carries_ip_and_rounded_location():
    from fortguard.admin import _network_of
    s = fresh_session()
    s.ip = "203.0.113.7"
    _note_location(s, {"lat": 24.86123, "lng": 67.00987, "accuracy_m": 18, "fix_age_s": 0}, 1_000_000)
    net = _network_of(s)
    assert net["ip"] == "203.0.113.7"
    assert net["location"] == {"lat": 24.86, "lng": 67.01, "accuracy_m": 18}
    assert net["location_jump"] is False
    assert _network_of(None)["location"] is None
