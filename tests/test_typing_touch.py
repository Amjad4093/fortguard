"""Typing speed, correction rate, touch pressure and size, tap rhythm and swipe speed.

Each value is checked against a hand calculation, and the incremental engine must agree with the
full calculation when the same events arrive split across batches.
"""

import math
import types

from fortguard.features import compute_features_full
from fortguard.incremental import FeatureState

PW, OTHER = "password", "other"


def _key(ts, field=PW, inserted=0, deleted=0):
    e = {"event_type": "DOWN", "ts": ts, "field": field}
    if inserted:
        e["inserted"] = inserted
    if deleted:
        e["deleted"] = deleted
    return e


def _touch(kind, ts, x=0.0, y=0.0, pressure=None, size=None):
    e = {"event_type": kind, "x": x, "y": y, "timestamp_ms": ts}
    if pressure is not None:
        e["pressure"] = pressure
    if size is not None:
        e["size"] = size
    return e


def _session(touch=(), keys=()):
    return types.SimpleNamespace(touch=list(touch), keys=list(keys), ui=[], accel=[], gyro=[])


def _close(a, b):
    assert a is not None and b is not None
    assert math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-9), (a, b)


def test_typing_speed_and_correction_by_hand():
    keys = [
        _key(0, inserted=1), _key(200, inserted=1), _key(450, inserted=1),   # gaps 200 + 250
        _key(600, deleted=1),                                               # backspace, gap 150
        _key(10_000, inserted=1),                                           # after a pause: not typing time
    ]
    f = compute_features_full(_session(keys=keys))
    # 4 characters inserted over 600 ms of active typing (200 + 250 + 150)
    _close(f["ft_typing_speed_cpm"], 4 * 60_000 / 600)
    # 1 deleted over 4 inserted
    _close(f["ft_correction_rate"], 1 / 4)


def test_a_change_of_field_is_not_typing_time():
    keys = [_key(0, inserted=1), _key(100, field=OTHER, inserted=1), _key(200, field=OTHER, inserted=1)]
    f = compute_features_full(_session(keys=keys))
    # only the 100 ms between the two "other" keystrokes counts
    _close(f["ft_typing_speed_cpm"], 3 * 60_000 / 100)


def test_no_character_counts_means_no_typing_metrics():
    f = compute_features_full(_session(keys=[_key(0), _key(300)]))
    assert f["ft_typing_speed_cpm"] is None and f["ft_correction_rate"] is None


def test_touch_pressure_size_taps_and_swipe_speed_by_hand():
    touch = [
        _touch("DOWN", 0, pressure=0.2, size=10),
        _touch("UP", 50, pressure=0.2, size=10),
        _touch("DOWN", 500, pressure=0.4, size=20),
        _touch("UP", 550, pressure=0.4, size=20),
        _touch("DOWN", 1200, pressure=0.6, size=30),
        _touch("UP", 1250, pressure=0.6, size=30),
        _touch("DOWN", 10_000, pressure=0.6, size=30),
        _touch("UP", 10_050, pressure=0.6, size=30),
    ]
    f = compute_features_full(_session(touch=touch))
    _close(f["ft_touch_pressure_mean"], (0.2 + 0.2 + 0.4 + 0.4 + 0.6 + 0.6 + 0.6 + 0.6) / 8)
    _close(f["ft_touch_size_mean"], (10 + 10 + 20 + 20 + 30 + 30 + 30 + 30) / 8)
    # taps: 500 ms and 700 ms apart count; the 8.8 s gap is a separate interaction
    _close(f["ft_tap_interval_mean_ms"], (500 + 700) / 2)


def test_swipe_speed_by_hand():
    swipe = [_touch("DOWN", 0, 0, 0), _touch("MOVE", 100, 100, 0), _touch("MOVE", 200, 200, 0), _touch("UP", 300, 300, 0)]
    f = compute_features_full(_session(touch=swipe))
    _close(f["ft_swipe_speed_px_s"], 300 / 300 * 1000)   # 300 px in 300 ms


def test_incremental_matches_full_when_split_across_batches():
    keys = [_key(i * 180, inserted=1) for i in range(8)] + [_key(1600, deleted=1), _key(9000, inserted=1)]
    touch = [
        _touch("DOWN", 0, 0, 0, pressure=0.3, size=12),
        _touch("MOVE", 100, 100, 0, pressure=0.5, size=14),
        _touch("MOVE", 200, 200, 0, pressure=0.5, size=14),
        _touch("UP", 300, 300, 0, pressure=0.4, size=12),
        _touch("DOWN", 700, 10, 10, pressure=0.6, size=9),
        _touch("UP", 760, 10, 10, pressure=0.6, size=9),
        _touch("DOWN", 1500, 50, 50, pressure=0.2, size=11),
        _touch("UP", 1560, 50, 50, pressure=0.2, size=11),
    ]
    state = FeatureState()
    # first batch ends mid-stream; the second continues it
    state.update([e for e in touch if e["timestamp_ms"] <= 700], [k for k in keys if k["ts"] <= 900], [], [], [])
    state.update([e for e in touch if e["timestamp_ms"] > 700], [k for k in keys if k["ts"] > 900], [], [], [])
    full = compute_features_full(_session(touch=touch, keys=keys))
    got = state.features()
    for name in (
        "ft_typing_speed_cpm", "ft_correction_rate", "ft_touch_pressure_mean", "ft_touch_pressure_std",
        "ft_touch_size_mean", "ft_tap_interval_mean_ms", "ft_swipe_speed_px_s",
    ):
        assert (got[name] is None) == (full[name] is None), name
        if full[name] is not None:
            _close(got[name], full[name])


def test_character_counts_are_range_checked_and_text_is_still_refused(api, enrolled, resign):
    session = enrolled()
    batch = __import__("copy").deepcopy(session["batches"][0])
    batch["key_events"] = [{"event_type": "DOWN", "ts": batch["timestamp_ms"], "field": "password", "inserted": 5000}]
    status, _ = api.post("/v1/telemetry/stream", resign(batch, session))
    assert status == 400
    batch["key_events"] = [{"event_type": "DOWN", "ts": batch["timestamp_ms"], "field": "password",
                            "inserted": 1, "text": "s3cret"}]
    status, _ = api.post("/v1/telemetry/stream", resign(batch, session))
    assert status == 422  # forbidden_field: typed text never reaches the server
