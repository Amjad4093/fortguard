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


def swipe_speeds(touch):
    """Speed in pixels per second for each swipe that swipe_deviations counts."""
    out = []
    for g in _gestures(touch):
        points = [(e["x"], e["y"]) for e in g]
        if len(points) < 4:
            continue
        length = math.hypot(points[-1][0] - points[0][0], points[-1][1] - points[0][1])
        if length < config.SWIPE_MIN_PX:
            continue
        duration = g[-1]["timestamp_ms"] - g[0]["timestamp_ms"]
        if duration > 0:
            out.append(length / duration * 1000.0)
    return out


def typing_totals(keys):
    """(characters inserted, characters deleted, active typing milliseconds) across one session.

    Only gaps between keystrokes in the same field count as typing time, and only when they are short
    enough to be typing rather than a pause.
    """
    inserted = deleted = 0
    active_ms = 0
    prev = None
    for e in sorted((e for e in keys if e["event_type"] == "DOWN"), key=lambda e: e["ts"]):
        inserted += e.get("inserted", 0)
        deleted += e.get("deleted", 0)
        if prev is not None and prev[1] == e.get("field"):
            gap = e["ts"] - prev[0]
            if 0 < gap <= config.TYPING_MAX_GAP_MS:
                active_ms += gap
        prev = (e["ts"], e.get("field"))
    return inserted, deleted, active_ms


def taps_of(touch):
    """(down_ms, up_ms) for each tap: a touch that ends within SWIPE_MIN_PX of where it began."""
    out = []
    for g in _gestures(touch):
        if math.hypot(g[-1]["x"] - g[0]["x"], g[-1]["y"] - g[0]["y"]) < config.SWIPE_MIN_PX:
            out.append((g[0]["timestamp_ms"], g[-1]["timestamp_ms"]))
    return out


def tap_summary(tap_list):
    """(durations_ms, long presses, double taps) from taps in time order."""
    durations = [up - down for down, up in tap_list]
    long_presses = sum(1 for d in durations if d >= config.LONG_PRESS_MS)
    double_taps = sum(1 for (_, up), (down, _) in zip(tap_list, tap_list[1:]) if 0 <= down - up < config.DOUBLE_TAP_MS)
    return durations, long_presses, double_taps


def tilt(mean_x, mean_y, mean_z, samples, variance):
    """(pitch degrees, roll degrees, lying flat 1.0 or 0.0) from the average pull of gravity.

    Pitch and roll say how the phone is held: flat on a desk reads near 0 and 0, upright in a hand reads
    a pitch or roll far from 0. "Lying flat" also needs the phone to be still. All None without samples.
    """
    if not samples:
        return None, None, None
    pitch = math.degrees(math.atan2(-mean_x, math.hypot(mean_y, mean_z)))
    roll = math.degrees(math.atan2(mean_y, mean_z))
    if samples < config.FLAT_MIN_SAMPLES or variance is None:
        return pitch, roll, None
    pull = math.sqrt(mean_x ** 2 + mean_y ** 2 + mean_z ** 2)
    flat = pull > 0 and abs(mean_z) / pull >= config.FLAT_GRAVITY_SHARE and variance <= config.FLAT_MAX_ACCEL_VAR
    return pitch, roll, 1.0 if flat else 0.0


def tap_intervals(touch):
    """Gaps in ms between consecutive touch-downs that are close enough to be one interaction."""
    downs = sorted(e["timestamp_ms"] for e in touch if e["event_type"] == "DOWN")
    return [b - a for a, b in zip(downs, downs[1:]) if 0 < b - a <= config.TAP_MAX_GAP_MS]


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


def step_cadence(accel):
    """(steps a second, walking 1.0 or 0.0) from a window of raw accelerometer samples.

    Walking shows as a steady rhythm in the size of the acceleration at step frequency. Returns
    (None, None) when the window is too short to tell, and (None, 0.0) when the customer is not walking.
    """
    if len(accel) < 32:
        return None, None
    ordered = sorted(accel, key=lambda s: s["ts"])
    span_s = (ordered[-1]["ts"] - ordered[0]["ts"]) / 1000.0
    if span_s < config.WALK_MIN_SPAN_S:
        return None, None
    fs = (len(ordered) - 1) / span_s
    low, high = config.WALK_BAND_HZ
    if fs / 2 <= high:
        return None, None
    mag = np.array([math.sqrt(s["x"] ** 2 + s["y"] ** 2 + s["z"] ** 2) for s in ordered])
    mag = mag - mag.mean()
    if float(mag.std()) < config.WALK_MIN_STD:
        return None, 0.0
    power = np.abs(np.fft.rfft(mag)) ** 2
    freqs = np.fft.rfftfreq(len(mag), d=1.0 / fs)
    total = power[1:].sum()
    in_band = (freqs >= low) & (freqs <= high)
    if total <= 0 or not in_band.any() or power[in_band].sum() / total < config.WALK_MIN_SHARE:
        return None, 0.0
    return float(freqs[in_band][int(np.argmax(power[in_band]))]), 1.0


def tap_offsets(touch):
    """How far each touch-down landed from the centre of the control it hit: 0 is dead centre, about 1 an edge."""
    return [math.hypot(e["tdx"], e["tdy"]) for e in touch if e["event_type"] == "DOWN" and "tdx" in e]


def field_marks(ui):
    """(time, field or None) for the events that start or end a stay in a field: focus, and submit (None)."""
    return [(e["ts"], None if e["event_type"] == "SUBMIT" else e.get("field", "other"))
            for e in ui if e["event_type"] in ("FOCUS", "SUBMIT")]


def field_times(marks):
    """Milliseconds spent in each field, from marks sorted by time: {field: total}, and every single stay.

    A stay runs from a focus to the next focus or submit, and counts for at most FIELD_TIME_CAP_MS. The
    last focus of a session has no end and is left out.
    """
    totals, stays = {}, []
    for (start, field), (end, _) in zip(marks, marks[1:]):
        if field is None:
            continue
        stay = min(max(0, end - start), config.FIELD_TIME_CAP_MS)
        totals[field] = totals.get(field, 0) + stay
        stays.append(stay)
    return totals, stays


def hesitation_marks(keys, ui):
    """(time, is_submit) for every event that matters to hesitation, unsorted.

    Payment inputs are keystrokes, focus and paste in payment fields. Sign-in fields and one-time-code
    fields are left out, and so are taps and scrolling: reading a screen is not hesitating over a payment.
    """
    ignored = config.HESITATION_IGNORED_FIELDS
    marks = [(e["ts"], False) for e in keys if e["event_type"] == "DOWN" and e.get("field") not in ignored]
    for e in ui:
        if e["event_type"] == "SUBMIT":
            marks.append((e["ts"], True))
        elif e.get("field") not in ignored:
            marks.append((e["ts"], False))
    return marks


def hesitation_from_marks(marks):
    """0 to 1 from marks sorted by time. See hesitation_index."""
    result = paused = 0.0
    last = None
    for ts, is_submit in marks:
        if is_submit:
            if last is not None:
                result = paused + _pause(ts - last)
            paused, last = 0.0, None       # the next input starts a new payment entry
        else:
            if last is not None:
                paused += _pause(ts - last)
            last = ts
    if last is not None:                   # an entry still being typed is the latest one
        result = paused
    return min(1.0, result / config.HESITATION_FULL_MS)


def _pause(gap):
    """Pause time beyond the think-time allowance, capped so one long break counts for little."""
    return min(max(0.0, gap - config.HESITATION_GAP_MS), config.HESITATION_PAUSE_CAP_MS)


def hesitation_index(keys, ui):
    """0 to 1. How long the customer paused while entering the latest payment.

    A payment entry runs from its first payment input to its submit. Within it, each gap between inputs
    counts only for the time beyond HESITATION_GAP_MS, at most HESITATION_PAUSE_CAP_MS per gap, and the
    total maps to 1.0 at HESITATION_FULL_MS. So the flag needs at least two long pauses in one entry.
    Time before the entry starts (signing in, browsing) and time after a submit never counts, so an
    earlier payment in the same session does not carry over.
    """
    return hesitation_from_marks(sorted(hesitation_marks(keys, ui)))


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
    inserted, deleted, active_ms = typing_totals(keys)
    pressures = [e["pressure"] for e in touch if "pressure" in e]
    sizes = [e["size"] for e in touch if "size" in e]
    taps = tap_intervals(touch)
    speeds = swipe_speeds(touch)
    tap_ms, long_presses, double_taps = tap_summary(taps_of(touch))
    accel = session.accel
    means = [statistics.fmean(s[axis] for s in accel) for axis in ("x", "y", "z")] if accel else [0.0, 0.0, 0.0]
    pitch, roll, flat = tilt(*means, len(accel), _variance_sum(accel))
    cadence, walking = step_cadence(recent_accel(accel))
    offsets = tap_offsets(touch)
    stays = field_times(sorted(field_marks(ui), key=lambda m: m[0]))[1]
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
        "ft_hesitation_index": hesitation_index(keys, ui),
        "ft_typing_speed_cpm": (inserted * 60000.0 / active_ms) if inserted and active_ms else None,
        "ft_correction_rate": min(1.0, deleted / max(inserted, 1)) if inserted or deleted else None,
        "ft_touch_pressure_mean": statistics.fmean(pressures) if pressures else None,
        "ft_touch_pressure_std": statistics.pstdev(pressures) if len(pressures) > 1 else None,
        "ft_touch_size_mean": statistics.fmean(sizes) if sizes else None,
        "ft_tap_interval_mean_ms": statistics.fmean(taps) if taps else None,
        "ft_swipe_speed_px_s": statistics.fmean(speeds) if speeds else None,
        "ft_tap_duration_mean_ms": statistics.fmean(tap_ms) if tap_ms else None,
        "ft_long_press_count": long_presses,
        "ft_double_tap_count": double_taps,
        "ft_tilt_pitch_deg": pitch,
        "ft_tilt_roll_deg": roll,
        "ft_lying_flat": flat,
        "ft_step_cadence_hz": cadence,
        "ft_walking": walking,
        "ft_tap_offset_mean": statistics.fmean(offsets) if offsets else None,
        "ft_autofill_count": sum(1 for e in ui if e["event_type"] == "AUTOFILL"),
        "ft_field_time_mean_ms": statistics.fmean(stays) if stays else None,
    }
