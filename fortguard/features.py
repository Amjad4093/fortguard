"""Behavioral features computed from one session's stored events.

Covers the five features named in BRD FR-ING-002, plus a few counts and a tremor-band ratio from
FR-SDK-002. These are plain functions over lists so they can be checked against hand calculations.
"""

import math
import statistics

import numpy as np

from . import config

SENSITIVE_PASTE_FIELDS = {"beneficiary_account", "amount", "otp"}


def _gestures(touch):
    gestures, current = [], None
    for e in sorted(touch, key=lambda e: e["timestamp_ms"]):
        kind = e["event_type"]
        if kind == "DOWN":
            current = [e]
        elif kind == "MOVE" and current is not None:
            current.append(e)
        elif kind == "UP" and current is not None:
            current.append(e)
            gestures.append(current)
            current = None
    return gestures


def _mean_deviation(points):
    """Mean distance of the path from the straight line between its first and last point."""
    (x0, y0), (x1, y1) = points[0], points[-1]
    length = math.hypot(x1 - x0, y1 - y0)
    if length == 0:
        return None
    total = sum(abs((x1 - x0) * (y0 - y) - (x0 - x) * (y1 - y0)) / length for x, y in points)
    return total / len(points)


def swipe_deviations(touch):
    """Mean path deviation (pixels) for each swipe: 4 or more points and 30 px or longer."""
    out = []
    for g in _gestures(touch):
        points = [(e["x"], e["y"]) for e in g]
        if len(points) < 4:
            continue
        if math.hypot(points[-1][0] - points[0][0], points[-1][1] - points[0][1]) < config.SWIPE_MIN_PX:
            continue
        dev = _mean_deviation(points)
        if dev is not None:
            out.append(dev)
    return out


def key_timings(keys):
    """Return (hold_times_ms, flight_times_ms). Flight = next press minus last release.

    A flight is only measured inside one field. Moving to another field is a pause to look at the
    screen, not typing rhythm, and would swamp the real spread.

    Android and iOS soft keyboards do not report key press and release, only that text changed, so
    the mobile SDKs send DOWN events alone. Two DOWNs in a row in one field are then measured press to
    press (inter-key interval), which keeps the scripted-typing rule working on real phones.
    """
    holds, flights = [], []
    pending_down, last_up, last_field = None, None, None
    for e in sorted(keys, key=lambda e: e["ts"]):
        if e["event_type"] == "DOWN":
            same_field = e.get("field") == last_field
            if pending_down is not None and same_field:
                flights.append(e["ts"] - pending_down)  # DOWN after DOWN: no release was reported
            elif last_up is not None and same_field:
                flights.append(e["ts"] - last_up)
            last_field = e.get("field")
            pending_down = e["ts"]
        else:
            if pending_down is not None:
                holds.append(e["ts"] - pending_down)
                pending_down = None
            last_up = e["ts"]
    return holds, flights


def _variance_sum(samples):
    if len(samples) < 2:
        return None
    return sum(
        statistics.pvariance([s[axis] for s in samples]) for axis in ("x", "y", "z")
    )


def _gyro_magnitude_variance(gyro):
    if len(gyro) < 2:
        return None
    return statistics.pvariance([math.sqrt(s["x"] ** 2 + s["y"] ** 2 + s["z"] ** 2) for s in gyro])


def tremor_band_ratio(accel):
    """Share of accelerometer power between 4 and 12 Hz. None when the samples cannot show it.

    Expects raw accelerometer samples that include gravity. Linear-acceleration streams (gravity
    removed) would be rectified by the magnitude step and need a different calculation.
    """
    if len(accel) < 32:
        return None
    ordered = sorted(accel, key=lambda s: s["ts"])
    span_s = (ordered[-1]["ts"] - ordered[0]["ts"]) / 1000.0
    if span_s <= 0:
        return None
    fs = (len(ordered) - 1) / span_s
    low, high = config.TREMOR_BAND_HZ
    if fs / 2 <= low:
        return None
    mag = np.array([math.sqrt(s["x"] ** 2 + s["y"] ** 2 + s["z"] ** 2) for s in ordered])
    mag = mag - mag.mean()
    power = np.abs(np.fft.rfft(mag)) ** 2
    freqs = np.fft.rfftfreq(len(mag), d=1.0 / fs)
    total = power[1:].sum()
    if total <= 0:
        return 0.0
    band = power[(freqs >= low) & (freqs <= min(high, fs / 2))].sum()
    return float(band / total)


def hesitation_index(touch, keys, ui):
    """0 to 1. Total time spent in pauses longer than 3 s between inputs, capped per pause.

    Session-wide for now: a person reading a screen also pauses. Narrowing this to the payment
    flow is a sprint 2 item.
    """
    times = sorted(
        [e["timestamp_ms"] for e in touch if e["event_type"] == "DOWN"]
        + [e["ts"] for e in keys if e["event_type"] == "DOWN"]
        + [e["ts"] for e in ui]
    )
    paused = 0.0
    for a, b in zip(times, times[1:]):
        gap = b - a
        if gap > config.HESITATION_GAP_MS:
            paused += min(gap, config.HESITATION_FULL_MS)
    return min(1.0, paused / config.HESITATION_FULL_MS)


def recent_accel(accel):
    """The most recent TREMOR_WINDOW samples, in time order (same window as the incremental engine)."""
    return sorted(accel, key=lambda s: s["ts"])[-config.TREMOR_WINDOW:]


def compute_features(session):
    """Features for a session: from the incremental state when it is valid, else from all events."""
    state = getattr(session, "fstate", None)
    if state is not None and not state.stale:
        return state.features()
    return compute_features_full(session)


def compute_features_full(session):
    touch, keys, ui = session.touch, session.keys, session.ui
    deviations = swipe_deviations(touch)
    holds, flights = key_timings(keys)
    pastes = [e for e in ui if e["event_type"] == "PASTE"]
    return {
        "ft_touch_count": sum(1 for e in touch if e["event_type"] == "DOWN"),
        "ft_swipe_count": len(deviations),
        "ft_swipe_curvature_mean_px": statistics.fmean(deviations) if deviations else None,
        "ft_swipe_curvature_max_px": max(deviations) if deviations else None,
        "ft_swipe_curvature_variance": statistics.pstdev(deviations) if len(deviations) > 1 else None,
        "ft_key_count": sum(1 for e in keys if e["event_type"] == "DOWN"),
        "ft_keystroke_hold_time_avg": statistics.fmean(holds) if holds else None,
        "ft_keystroke_flight_time_avg": statistics.fmean(flights) if flights else None,
        "ft_keystroke_flight_time_std": statistics.pstdev(flights) if len(flights) > 1 else None,
        "ft_keystroke_flight_count": len(flights),
        "ft_device_angle_stability": _gyro_magnitude_variance(session.gyro),
        "ft_accel_variance": _variance_sum(session.accel),
        "ft_gyro_variance": _variance_sum(session.gyro),
        "ft_accel_samples": len(session.accel),
        "ft_tremor_band_ratio": tremor_band_ratio(recent_accel(session.accel)),
        "ft_pasting_frequency": sum(1 for e in pastes if e.get("field") in SENSITIVE_PASTE_FIELDS),
        "ft_paste_beneficiary_count": sum(1 for e in pastes if e.get("field") == "beneficiary_account"),
        "ft_hesitation_index": hesitation_index(touch, keys, ui),
    }
