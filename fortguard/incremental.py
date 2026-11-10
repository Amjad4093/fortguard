"""Incremental feature engine: features are updated as each telemetry batch arrives.

Evaluate then reads finished numbers instead of re-reading the whole session history, which keeps
scoring time flat however long a session runs (backlog E2-04 and E4-02; see the load test in README).

The results equal features.compute_features() on the same events, provided batches arrive in time
order, as a well-behaved SDK sends them. If an event ever arrives earlier than one already processed
(a retried batch, a misbehaving client), the state marks itself stale and scoring falls back to the
full calculation for that session, so correctness never depends on arrival order.
tests/test_incremental.py checks the equality on every synthetic scenario.
"""

import bisect
import math
from collections import deque

import numpy as np

from . import config

SENSITIVE_PASTE_FIELDS = {"beneficiary_account", "amount", "otp"}


class Running:
    """Welford running mean and population variance, plus max."""

    __slots__ = ("n", "mean", "m2", "max")

    def __init__(self):
        self.n, self.mean, self.m2, self.max = 0, 0.0, 0.0, None

    def add(self, x):
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)
        self.max = x if self.max is None or x > self.max else self.max

    def merge(self, n, mean, m2, mx):
        """Combine with another set's count, mean, sum of squared deviations and max (Chan et al.)."""
        if n == 0:
            return
        if self.n == 0:
            self.n, self.mean, self.m2, self.max = n, mean, m2, mx
            return
        total = self.n + n
        delta = mean - self.mean
        self.mean += delta * n / total
        self.m2 += m2 + delta * delta * self.n * n / total
        self.n = total
        self.max = mx if self.max is None or mx > self.max else self.max

    def merge_array(self, arr):
        if len(arr):
            mean = float(arr.mean())
            self.merge(len(arr), mean, float(((arr - mean) ** 2).sum()), float(arr.max()))

    def pvariance(self):
        return self.m2 / self.n if self.n else None

    def pstdev(self):
        return math.sqrt(self.m2 / self.n) if self.n else None


class FeatureState:
    def __init__(self):
        self.stale = False
        # touch
        self.touch_downs = 0
        self.gesture = None            # points of the gesture in progress
        self.swipes = Running()
        self.last_touch_ts = None
        # keys
        self.key_downs = 0
        self.pending_down = None
        self.last_up = None
        self.last_field = None
        self.holds = Running()
        self.flights = Running()
        self.last_key_ts = None
        # ui
        self.paste_sensitive = 0
        self.paste_beneficiary = 0
        # hesitation (touch DOWN, key DOWN and all UI events). Kept as a sorted list of times so the
        # result is exact in any arrival order: inserting a time only changes the gaps next to it.
        self.input_times = []
        self.paused_ms = 0.0
        # sensors
        self.accel_axes = [Running(), Running(), Running()]
        self.gyro_axes = [Running(), Running(), Running()]
        self.gyro_mag = Running()
        self.accel_recent = deque(maxlen=config.TREMOR_WINDOW)
        self.last_accel_ts = None
        self.last_gyro_ts = None
        # typing (character counts only), touch pressure and size, taps and swipe speed
        self.typed_inserted = 0
        self.typed_deleted = 0
        self.typing_active_ms = 0
        self.prev_down = None          # (ts, field) of the last key DOWN, in any field
        self.pressure = Running()
        self.touch_size = Running()
        self.taps = Running()
        self.last_tap_down = None
        self.gesture_ts = None         # timestamps of the gesture in progress
        self.swipe_speed = Running()

    # --- updates ---------------------------------------------------------------------------

    def update(self, touch, keys, ui, accel, gyro):
        if self.stale:
            return
        touch = sorted(touch, key=lambda e: e["timestamp_ms"])
        keys = sorted(keys, key=lambda e: e["ts"])
        accel = sorted(accel, key=lambda s: s["ts"])
        gyro = sorted(gyro, key=lambda s: s["ts"])
        inputs = sorted(
            [e["timestamp_ms"] for e in touch if e["event_type"] == "DOWN"]
            + [e["ts"] for e in keys if e["event_type"] == "DOWN"]
            + [e["ts"] for e in ui]
        )
        if (self._before(touch, "timestamp_ms", self.last_touch_ts) or self._before(keys, "ts", self.last_key_ts)
                or self._before(accel, "ts", self.last_accel_ts) or self._before(gyro, "ts", self.last_gyro_ts)):
            self.stale = True
            return
        self._touch(touch)
        self._keys(keys)
        for e in ui:
            if e["event_type"] == "PASTE":
                self.paste_sensitive += e.get("field") in SENSITIVE_PASTE_FIELDS
                self.paste_beneficiary += e.get("field") == "beneficiary_account"
        for t in inputs:
            self._insert_input_time(t)
        # Sensor batches are summarised with numpy and merged: exact, and far cheaper than per sample.
        if accel:
            a = np.array([(s["x"], s["y"], s["z"]) for s in accel], dtype=float)
            for i, r in enumerate(self.accel_axes):
                r.merge_array(a[:, i])
            self.accel_recent.extend(accel)
        if gyro:
            gy = np.array([(s["x"], s["y"], s["z"]) for s in gyro], dtype=float)
            for i, r in enumerate(self.gyro_axes):
                r.merge_array(gy[:, i])
            self.gyro_mag.merge_array(np.sqrt((gy ** 2).sum(axis=1)))
        if accel:
            self.last_accel_ts = accel[-1]["ts"]
        if gyro:
            self.last_gyro_ts = gyro[-1]["ts"]

    @staticmethod
    def _pause(a, b):
        gap = b - a
        return min(gap, config.HESITATION_FULL_MS) if gap > config.HESITATION_GAP_MS else 0.0

    def _insert_input_time(self, t):
        times = self.input_times
        i = bisect.bisect_right(times, t)
        before = times[i - 1] if i > 0 else None
        after = times[i] if i < len(times) else None
        if before is not None and after is not None:
            self.paused_ms -= self._pause(before, after)
        if before is not None:
            self.paused_ms += self._pause(before, t)
        if after is not None:
            self.paused_ms += self._pause(t, after)
        times.insert(i, t)

    @staticmethod
    def _before(items, key, last):
        return bool(items) and last is not None and items[0][key] < last

    def _touch(self, touch):
        from .features import _mean_deviation

        for e in touch:
            kind = e["event_type"]
            ts = e["timestamp_ms"]
            if "pressure" in e:
                self.pressure.add(e["pressure"])
            if "size" in e:
                self.touch_size.add(e["size"])
            if kind == "DOWN":
                self.touch_downs += 1
                self.gesture = [(e["x"], e["y"])]
                self.gesture_ts = [ts]
                if self.last_tap_down is not None:
                    gap = ts - self.last_tap_down
                    if 0 < gap <= config.TAP_MAX_GAP_MS:
                        self.taps.add(gap)
                self.last_tap_down = ts
            elif kind == "MOVE" and self.gesture is not None:
                self.gesture.append((e["x"], e["y"]))
                self.gesture_ts.append(ts)
            elif kind == "UP" and self.gesture is not None:
                self.gesture.append((e["x"], e["y"]))
                self.gesture_ts.append(ts)
                pts = self.gesture
                self.gesture = None
                if len(pts) >= 4 and math.hypot(pts[-1][0] - pts[0][0], pts[-1][1] - pts[0][1]) >= config.SWIPE_MIN_PX:
                    dev = _mean_deviation(pts)
                    if dev is not None:
                        self.swipes.add(dev)
                        duration = self.gesture_ts[-1] - self.gesture_ts[0]
                        if duration > 0:
                            length = math.hypot(pts[-1][0] - pts[0][0], pts[-1][1] - pts[0][1])
                            self.swipe_speed.add(length / duration * 1000.0)
                self.gesture_ts = None
            self.last_touch_ts = ts

    def _keys(self, keys):
        for e in keys:
            if e["event_type"] == "DOWN":
                self.key_downs += 1
                self.typed_inserted += e.get("inserted", 0)
                self.typed_deleted += e.get("deleted", 0)
                if self.prev_down is not None and self.prev_down[1] == e.get("field"):
                    gap = e["ts"] - self.prev_down[0]
                    if 0 < gap <= config.TYPING_MAX_GAP_MS:
                        self.typing_active_ms += gap
                self.prev_down = (e["ts"], e.get("field"))
                same = e.get("field") == self.last_field
                if self.pending_down is not None and same:
                    self.flights.add(e["ts"] - self.pending_down)
                elif self.last_up is not None and same:
                    self.flights.add(e["ts"] - self.last_up)
                self.last_field = e.get("field")
                self.pending_down = e["ts"]
            else:
                if self.pending_down is not None:
                    self.holds.add(e["ts"] - self.pending_down)
                    self.pending_down = None
                self.last_up = e["ts"]
            self.last_key_ts = e["ts"]

    # --- read out ------------------------------------------------------------------------------

    def features(self):
        from .features import tremor_band_ratio

        def var_sum(axes):
            return sum(r.pvariance() for r in axes) if axes[0].n >= 2 else None

        s, f, h = self.swipes, self.flights, self.holds
        return {
            "ft_touch_count": self.touch_downs,
            "ft_swipe_count": s.n,
            "ft_swipe_curvature_mean_px": s.mean if s.n else None,
            "ft_swipe_curvature_max_px": s.max,
            "ft_swipe_curvature_variance": s.pstdev() if s.n > 1 else None,
            "ft_key_count": self.key_downs,
            "ft_keystroke_hold_time_avg": h.mean if h.n else None,
            "ft_keystroke_flight_time_avg": f.mean if f.n else None,
            "ft_keystroke_flight_time_std": f.pstdev() if f.n > 1 else None,
            "ft_keystroke_flight_count": f.n,
            "ft_device_angle_stability": self.gyro_mag.pvariance() if self.gyro_mag.n >= 2 else None,
            "ft_accel_variance": var_sum(self.accel_axes),
            "ft_gyro_variance": var_sum(self.gyro_axes),
            "ft_accel_samples": self.accel_axes[0].n,
            "ft_tremor_band_ratio": tremor_band_ratio(list(self.accel_recent)),
            "ft_pasting_frequency": self.paste_sensitive,
            "ft_paste_beneficiary_count": self.paste_beneficiary,
            "ft_hesitation_index": min(1.0, self.paused_ms / config.HESITATION_FULL_MS),
            "ft_typing_speed_cpm": (self.typed_inserted * 60000.0 / self.typing_active_ms
                                    if self.typed_inserted and self.typing_active_ms else None),
            "ft_correction_rate": (min(1.0, self.typed_deleted / max(self.typed_inserted, 1))
                                   if self.typed_inserted or self.typed_deleted else None),
            "ft_touch_pressure_mean": self.pressure.mean if self.pressure.n else None,
            "ft_touch_pressure_std": self.pressure.pstdev() if self.pressure.n > 1 else None,
            "ft_touch_size_mean": self.touch_size.mean if self.touch_size.n else None,
            "ft_tap_interval_mean_ms": self.taps.mean if self.taps.n else None,
            "ft_swipe_speed_px_s": self.swipe_speed.mean if self.swipe_speed.n else None,
        }
