"""Feature calculations checked against hand-worked numbers."""

import math

import pytest

from fortguard import config, features


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


def _keys_at(*times, field="beneficiary_account"):
    return [{"event_type": "DOWN", "field": field, "ts": t} for t in times]


def _ui(kind, ts, field="other"):
    return {"event_type": kind, "field": field, "ts": ts}


def test_hesitation_index_by_hand():
    # Two pauses inside one payment entry: 7 s (4 s beyond the 3 s allowance) and 5 s (2 s beyond).
    keys = _keys_at(0, 7_000, 12_000)
    assert features.hesitation_index(keys, []) == pytest.approx(0.6)


def test_short_gaps_are_not_hesitation():
    keys = _keys_at(0, 1000, 2500, 5000)
    assert features.hesitation_index(keys, []) == 0.0


def test_fast_typing_is_never_hesitation():
    keys = _keys_at(*range(0, 60_000, 150))  # about 400 keystrokes a minute, steady
    assert features.hesitation_index(keys, []) == 0.0


def test_hesitation_index_is_capped_at_one():
    keys = _keys_at(0, 60_000, 120_000, 180_000)
    assert features.hesitation_index(keys, []) == 1.0


def test_one_long_break_alone_never_reaches_the_flag():
    # Leaving the app to copy an account number: one very long gap, then steady typing.
    keys = _keys_at(0, 300, 120_000, 120_300, 120_600)
    assert features.hesitation_index(keys, []) == pytest.approx(0.5)
    assert features.hesitation_index(keys, []) < config.HESITATION_FLAG


def test_time_before_the_payment_form_is_not_hesitation():
    # The bug this replaces: tapping the sign-in box, browsing for 25 s, then typing a payment steadily.
    ui = [_ui("FOCUS", 0, "username"), _ui("FOCUS", 25_000, "beneficiary_account"), _ui("SUBMIT", 31_000)]
    keys = _keys_at(*range(25_400, 30_000, 350))
    assert features.hesitation_index(keys, ui) == 0.0


def test_sign_in_and_one_time_code_fields_are_ignored():
    keys = _keys_at(0, 9_000, 18_000, field="password") + _keys_at(30_000, 39_000, 48_000, field="otp")
    assert features.hesitation_index(keys, []) == 0.0


def test_an_earlier_payment_does_not_carry_over():
    # First entry is full of long pauses and is submitted. The second is typed steadily.
    first = _keys_at(0, 9_000, 18_000, 27_000)
    second = _keys_at(60_000, 60_300, 60_600, 60_900)
    ui = [_ui("SUBMIT", 28_000), _ui("SUBMIT", 61_500)]
    assert features.hesitation_index(first, [ui[0]]) == 1.0
    assert features.hesitation_index(first + second, ui) == 0.0


def test_the_wait_before_pressing_send_counts():
    keys = _keys_at(0, 8_000)                       # 5 s beyond the allowance
    ui = [_ui("SUBMIT", 14_000)]                     # 3 s beyond the allowance
    assert features.hesitation_index(keys, ui) == pytest.approx(0.8)


def test_an_entry_still_being_typed_is_the_one_measured():
    done = _keys_at(0, 300, 600)
    typing_now = _keys_at(20_000, 28_000, 36_000)
    assert features.hesitation_index(done + typing_now, [_ui("SUBMIT", 1_000)]) == 1.0



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


def test_incremental_hesitation_matches_in_any_arrival_order():
    """Batches can arrive split anywhere; the running value must equal the one-shot calculation."""
    from fortguard.incremental import FeatureState

    keys = _keys_at(0, 9_000, 18_000) + _keys_at(60_000, 60_300, 68_000, 76_500, field="amount")
    ui = [_ui("FOCUS", -500, "username"), _ui("SUBMIT", 19_000), _ui("FOCUS", 59_000, "amount")]
    want = features.hesitation_index(keys, ui)
    assert want == pytest.approx(0.97)   # second entry only: 4.7 s and 5 s beyond the allowance
    state = FeatureState()
    state.update([], keys[:2], [ui[2]], [], [])
    state.update([], keys[2:5], ui[:2], [], [])
    state.update([], keys[5:], [], [], [])
    assert state.features()["ft_hesitation_index"] == pytest.approx(want)


# --- Taps, long presses, double taps and tilt (derived from the raw touch and motion events) ------

def _tap(down, up, x=100, y=200, dx=0):
    return [{"event_type": "DOWN", "x": x, "y": y, "timestamp_ms": down},
            {"event_type": "UP", "x": x + dx, "y": y, "timestamp_ms": up}]


def test_tap_durations_long_presses_and_double_taps_by_hand():
    touch = (_tap(0, 80) + _tap(200, 290)          # second starts 120 ms after the first ended: a double tap
             + _tap(2_000, 2_700)                  # held 700 ms: a long press
             + _tap(5_000, 5_100, dx=200))         # moved 200 px: a swipe, not a tap
    durations, long_presses, double_taps = features.tap_summary(features.taps_of(touch))
    assert durations == [80, 90, 700]
    assert long_presses == 1
    assert double_taps == 1


def test_a_phone_lying_still_on_a_desk_reads_flat():
    pitch, roll, flat = features.tilt(0.02, -0.03, 9.80, 200, 0.001)
    assert abs(pitch) < 1 and abs(roll) < 1 and flat == 1.0


def test_a_phone_held_upright_is_not_flat():
    pitch, roll, flat = features.tilt(0.3, 8.5, 4.9, 200, 0.4)
    assert roll == pytest.approx(60.0, abs=1.0)
    assert flat == 0.0


def test_a_flat_but_moving_phone_is_not_lying_flat():
    assert features.tilt(0.0, 0.0, 9.8, 200, 0.5)[2] == 0.0


def test_tilt_is_unknown_without_motion_data():
    assert features.tilt(0.0, 0.0, 0.0, 0, None) == (None, None, None)
    assert features.tilt(0.0, 0.0, 9.8, 5, 0.001)[2] is None       # too few samples to call it flat


# --- Walking, time in a field, tap offset, autofill ---------------------------------------------------

def _accel(seconds, hz, wave):
    # Walking bounces the phone along gravity, so the wave is added to the axis gravity is on.
    return [{"x": 0.0, "y": 0.0, "z": 9.81 + wave(i / hz), "ts": int(i * 1000 / hz)} for i in range(int(seconds * hz))]


def test_a_steady_two_steps_a_second_is_walking():
    import math
    cadence, walking = features.step_cadence(_accel(6, 50, lambda t: 2.5 * math.sin(2 * math.pi * 2.0 * t)))
    assert walking == 1.0 and cadence == pytest.approx(2.0, abs=0.2)


def test_a_phone_held_still_or_shaken_fast_is_not_walking():
    import math
    assert features.step_cadence(_accel(6, 50, lambda t: 0.02 * math.sin(2 * math.pi * 2.0 * t))) == (None, 0.0)
    assert features.step_cadence(_accel(6, 50, lambda t: 2.5 * math.sin(2 * math.pi * 9.0 * t))) == (None, 0.0)


def test_too_little_motion_data_gives_no_answer_about_walking():
    assert features.step_cadence(_accel(1, 50, lambda t: 2.0)) == (None, None)
    assert features.step_cadence([]) == (None, None)


def test_time_in_a_field_runs_from_focus_to_the_next_focus_or_submit():
    ui = [_ui("FOCUS", 1_000, "beneficiary_account"), _ui("PASTE", 2_000, "beneficiary_account"),
          _ui("FOCUS", 9_000, "amount"), _ui("SUBMIT", 12_000), _ui("FOCUS", 20_000, "amount")]
    totals, stays = features.field_times(sorted(features.field_marks(ui)))
    assert totals == {"beneficiary_account": 8_000, "amount": 3_000}   # the last focus has no end yet
    assert stays == [8_000, 3_000]


def test_one_stay_in_a_field_is_capped():
    ui = [_ui("FOCUS", 0, "amount"), _ui("SUBMIT", 10 * 60_000)]
    assert features.field_times(sorted(features.field_marks(ui), key=lambda m: m[0]))[1] == [config.FIELD_TIME_CAP_MS]


def test_tap_offset_is_the_distance_from_the_centre_of_the_control():
    touch = [{"event_type": "DOWN", "x": 1, "y": 1, "timestamp_ms": 1, "tdx": 0.3, "tdy": -0.4},
             {"event_type": "DOWN", "x": 1, "y": 1, "timestamp_ms": 2},                       # control not known
             {"event_type": "UP", "x": 1, "y": 1, "timestamp_ms": 3}]
    assert features.tap_offsets(touch) == [pytest.approx(0.5)]
