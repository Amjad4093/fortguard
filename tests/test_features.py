"""Feature calculations checked against hand-worked numbers."""

import math

import pytest

from fortguard import features


def pt(kind, x, y, t):
    return {"event_type": kind, "x": x, "y": y, "timestamp_ms": t}


def test_straight_swipe_has_zero_deviation():
    touch = [pt("DOWN", 0, 0, 0), pt("MOVE", 0, 50, 10), pt("MOVE", 0, 100, 20),
             pt("MOVE", 0, 150, 30), pt("UP", 0, 200, 40)]
    assert features.swipe_deviations(touch) == [0.0]


def test_bowed_swipe_deviation_by_hand():
    # Line from (0,0) to (0,200). Points sit 0, 10, 20, 10, 0 px off the line: mean = 8.0.
    touch = [pt("DOWN", 0, 0, 0), pt("MOVE", 10, 50, 10), pt("MOVE", 20, 100, 20),
             pt("MOVE", 10, 150, 30), pt("UP", 0, 200, 40)]
    assert features.swipe_deviations(touch) == pytest.approx([8.0])


def test_tap_is_not_a_swipe():
    touch = [pt("DOWN", 5, 5, 0), pt("MOVE", 6, 6, 10), pt("MOVE", 6, 7, 20), pt("UP", 6, 7, 30)]
    assert features.swipe_deviations(touch) == []


def test_key_hold_and_flight_times_by_hand():
    keys = [
        {"event_type": "DOWN", "ts": 1000, "field": "otp"}, {"event_type": "UP", "ts": 1090, "field": "otp"},
        {"event_type": "DOWN", "ts": 1300, "field": "otp"}, {"event_type": "UP", "ts": 1380, "field": "otp"},
    ]
    holds, flights = features.key_timings(keys)
    assert holds == [90, 80]
    assert flights == [210]  # 1300 - 1090


def test_flight_time_is_not_measured_across_fields():
    keys = [
        {"event_type": "DOWN", "ts": 1000, "field": "beneficiary_account"},
        {"event_type": "UP", "ts": 1090, "field": "beneficiary_account"},
        {"event_type": "DOWN", "ts": 9000, "field": "amount"},
        {"event_type": "UP", "ts": 9080, "field": "amount"},
    ]
    assert features.key_timings(keys)[1] == []


def _keys_at(*times):
    return [{"event_type": "DOWN", "ts": t, "field": "amount"} for t in times]


def test_hesitation_index_by_hand():
    keys = _keys_at(0, 10_000)  # one 10 s pause between keystrokes
    ui = [{"event_type": "FOCUS", "field": "amount", "ts": 15_000}]  # then a 5 s pause before focus
    # (10000 + 5000) / 20000 = 0.75
    assert features.hesitation_index(keys, ui) == pytest.approx(0.75)


def test_short_gaps_are_not_hesitation():
    keys = _keys_at(0, 1000, 2500, 5000)
    assert features.hesitation_index(keys, []) == 0.0


def test_fast_typing_is_never_hesitation():
    keys = _keys_at(*range(0, 60_000, 150))  # about 400 keystrokes a minute, steady
    assert features.hesitation_index(keys, []) == 0.0


def test_hesitation_index_is_capped_at_one():
    keys = _keys_at(0, 60_000, 120_000)
    assert features.hesitation_index(keys, []) == 1.0


def _accel_with_gravity(freq_hz, fs=50, seconds=4):
    # Raw accelerometer data includes gravity (about 9.81 on one axis), so the magnitude follows the
    # shake linearly. Without gravity the magnitude would rectify the signal and double its frequency.
    return [{"x": 0.0, "y": 9.81 + 0.5 * math.sin(2 * math.pi * freq_hz * i / fs), "z": 0.0,
             "ts": int(i * 1000 / fs)} for i in range(fs * seconds)]


def test_tremor_band_ratio_finds_an_8hz_signal():
    assert features.tremor_band_ratio(_accel_with_gravity(8)) > 0.9


def test_tremor_band_ratio_ignores_a_1hz_signal():
    assert features.tremor_band_ratio(_accel_with_gravity(1)) < 0.1


def test_tremor_ratio_is_none_when_samples_cannot_show_it():
    assert features.tremor_band_ratio([]) is None
    slow = [{"x": 0.0, "y": 0.0, "z": 0.0, "ts": i * 500} for i in range(40)]  # 2 Hz sampling
    assert features.tremor_band_ratio(slow) is None


def test_soft_keyboard_down_only_events_give_press_to_press_intervals():
    keys = [{"event_type": "DOWN", "ts": t, "field": "amount"} for t in (1000, 1180, 1420, 1600)]
    holds, flights = features.key_timings(keys)
    assert holds == []
    assert flights == [180, 240, 180]


def test_soft_keyboard_intervals_do_not_cross_fields():
    keys = [{"event_type": "DOWN", "ts": 1000, "field": "beneficiary_account"},
            {"event_type": "DOWN", "ts": 1200, "field": "beneficiary_account"},
            {"event_type": "DOWN", "ts": 9000, "field": "amount"},
            {"event_type": "DOWN", "ts": 9150, "field": "amount"}]
    assert features.key_timings(keys)[1] == [200, 150]


def test_scripted_rule_fires_on_robotic_soft_keyboard_input(api, enrolled, resign):
    session = enrolled("genuine")
    batch = session["batches"][0]
    batch["key_events"] = [{"event_type": "DOWN", "ts": batch["timestamp_ms"] - 5000 + i * 100, "field": "amount"}
                           for i in range(12)]
    assert api.post("/v1/telemetry/stream", resign(batch, session))[0] == 202
    for b in session["batches"][1:]:
        b = dict(b); b["key_events"] = []
        api.post("/v1/telemetry/stream", resign(b, session))
    _, body = api.post("/v1/risk/evaluate", session["evaluate"], auth=True)
    assert "REASON_SCRIPTED_INPUT" in body["reason_codes"]
