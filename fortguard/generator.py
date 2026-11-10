"""Synthetic labeled sessions for pipeline and rule tests (backlog item E3-01).

These sessions are invented from simple models of how people and scripts behave. They prove that
the plumbing and the rules work as written. They say nothing about how real customers or real
attackers behave, so detection results on this data must not be quoted as expected fraud performance.
"""

import math
import random

from .simdevice import DEFAULT_APP_ID, SimDevice

SCENARIOS = (
    "genuine",
    "genuine_new_payee",
    "bot_scripted",
    "emulator_bot",
    "remote_control",
    "coached_scam",
    "rooted_device",
    "no_consent",
)

# Lowest acceptable decision for each scenario (the rules must reach at least this level).
EXPECTED_AT_LEAST = {
    "genuine": "ALLOW",
    "genuine_new_payee": "ALLOW",
    "bot_scripted": "BLOCK",
    "emulator_bot": "STEP_UP",
    "remote_control": "STEP_UP",
    "coached_scam": "STEP_UP",
    "rooted_device": "STEP_UP",
    "no_consent": "ALLOW",
}
# Highest acceptable level, used to check that genuine sessions are left alone.
EXPECTED_AT_MOST = {"genuine": "ALLOW", "genuine_new_payee": "ALLOW", "no_consent": "ALLOW"}

ORDER = {"ALLOW": 0, "STEP_UP": 1, "BLOCK": 2}
MS = 1000.0
SAMPLE_PERIOD_MS = 50  # 20 Hz


def _ident(rng, prefix, size=12):
    return prefix + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(size))


def _swipes(rng, t, count, human):
    events = []
    for _ in range(count):
        x0, y0 = rng.uniform(200, 600), rng.uniform(900, 1400)
        angle = rng.uniform(-0.3, 0.3)
        length = rng.uniform(250, 600)
        points = 10
        events.append({"event_type": "DOWN", "x": x0, "y": y0,
                       "pressure": rng.uniform(0.3, 0.8) if human else 0.5,
                       "size": rng.uniform(0.2, 0.5) if human else 0.3, "timestamp_ms": int(t)})
        for i in range(1, points):
            f = i / points
            along = length * f
            bow = math.sin(f * math.pi) * rng.uniform(8, 28) if human else 0.0
            jitter = rng.gauss(0, 2.5) if human else 0.0
            x = x0 + along * math.sin(angle) + (bow + jitter) * math.cos(angle)
            y = y0 - along * math.cos(angle) + (bow + jitter) * math.sin(angle)
            step = rng.uniform(12, 25) if human else 10
            events.append({"event_type": "MOVE", "x": x, "y": y,
                           "pressure": rng.uniform(0.3, 0.8) if human else 0.5,
                           "size": rng.uniform(0.2, 0.5) if human else 0.3,
                           "timestamp_ms": int(t + i * step)})
        events.append({"event_type": "UP", "x": x0 + length * math.sin(angle),
                       "y": y0 - length * math.cos(angle), "pressure": 0.0,
                       "timestamp_ms": int(t + points * (18 if human else 10))})
        t += rng.uniform(700, 1600) if human else 400
    return events, t


def _typing(rng, t, count, field, human):
    events = []
    for i in range(count):
        hold = max(30, rng.gauss(90, 20)) if human else 1
        flight = max(40, rng.gauss(190, 60)) if human else 2
        # Character counts, as the SDK sends them: a typed character, or a correction (backspace) now and then.
        correction = human and i % 9 == 8
        events.append({"event_type": "DOWN", "ts": int(t), "field": field,
                       "inserted": 0 if correction else 1, "deleted": 1 if correction else 0})
        events.append({"event_type": "UP", "ts": int(t + hold), "field": field})
        t += hold + flight
    return events, t


def _sensors(rng, start_ms, seconds, human):
    accel, gyro = [], []
    n = int(seconds * MS / SAMPLE_PERIOD_MS)
    phase = rng.uniform(0, 6.28)
    for i in range(n):
        ts = int(start_ms + i * SAMPLE_PERIOD_MS)
        if human:
            tremor = 0.04 * math.sin(2 * math.pi * 8.0 * (i * SAMPLE_PERIOD_MS / MS) + phase)
            accel.append({"x": rng.gauss(0.1, 0.05) + tremor, "y": 9.81 + rng.gauss(0, 0.06),
                          "z": rng.gauss(0.2, 0.05), "ts": ts})
            gyro.append({"x": rng.gauss(0, 0.012), "y": rng.gauss(0, 0.012),
                         "z": rng.gauss(0, 0.012), "ts": ts})
        else:
            accel.append({"x": 0.0, "y": 9.81, "z": 0.0, "ts": ts})
            gyro.append({"x": 0.0, "y": 0.0, "z": 0.0, "ts": ts})
    return {"accelerometer": accel, "gyroscope": gyro}


# Phone models for the synthetic devices, so the back office has real-looking model names to show.
DEVICE_MODELS = ("Pixel 8", "SM-S921B", "Pixel 7a", "SM-A546E", "Redmi Note 13")


def _env(**flags):
    env = {"os": "Android", "os_version": "15.0", "is_rooted": False, "is_emulator": False,
           "has_hooking_framework": False, "active_remote_software": False,
           "screen_sharing": False, "active_call": False, "vpn": False, "mock_location": False}
    env.update(flags)
    return env


def build_session(scenario, now_ms, seed=0, device=None):
    """Return one labeled session: signed telemetry batches plus the matching evaluate request.

    The device signs its own batches with its own key. It must be enrolled before the batches are
    sent (see client.enroll_device).
    """
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}")
    rng = random.Random(f"{scenario}:{seed}")
    device = device or SimDevice(f"{scenario}:{seed}")
    session_id, device_guid = _ident(rng, "sess_"), device.device_guid
    user_id = _ident(rng, "usr_", 8)
    t = now_ms - 90_000
    new_payee = scenario in ("genuine_new_payee", "coached_scam", "remote_control", "bot_scripted")
    human = scenario in ("genuine", "genuine_new_payee", "coached_scam", "rooted_device", "no_consent",
                         "remote_control")

    env = _env()
    env["device_model"] = DEVICE_MODELS[sum(map(ord, device.device_guid)) % len(DEVICE_MODELS)]
    if scenario == "emulator_bot":
        env.update(is_emulator=True)
    if scenario == "remote_control":
        env.update(active_remote_software=True, screen_sharing=True)
    if scenario == "coached_scam":
        env.update(active_call=True)
    if scenario == "rooted_device":
        env.update(is_rooted=True)

    touch, t = _swipes(rng, t, 6, human)
    keys, ui = [], []
    ui.append({"event_type": "FOCUS", "field": "beneficiary_account", "ts": int(t)})
    typed, t = _typing(rng, t + 400, 10, "beneficiary_account", human)
    keys += typed
    if scenario == "coached_scam":
        # The caller dictates the details: long silences between steps.
        t += rng.uniform(6000, 9000)
        ui.append({"event_type": "FOCUS", "field": "amount", "ts": int(t)})
        more, t = _typing(rng, t + 400, 6, "amount", True)
        keys += more
        t += rng.uniform(6000, 9000)
    else:
        ui.append({"event_type": "FOCUS", "field": "amount", "ts": int(t)})
        more, t = _typing(rng, t + 600, 5, "amount", human)
        keys += more
    ui.append({"event_type": "SUBMIT", "field": "other", "ts": int(t + 300)})

    sensors = _sensors(rng, now_ms - 90_000, 80, human and scenario != "emulator_bot")
    if scenario == "remote_control":
        touch = touch[:12]  # almost no real touch: the input arrives from the remote side

    consent = {"behavioral": scenario != "no_consent"}
    half = len(touch) // 2
    batches = []
    for index, (touch_part, key_part, ui_part, sensor_part) in enumerate(
        [
            (touch[:half], keys[: len(keys) // 2], ui[:1], _slice(sensors, 0, 0.5)),
            (touch[half:], keys[len(keys) // 2:], ui[1:], _slice(sensors, 0.5, 1.0)),
        ]
    ):
        payload = {
            "session_id": session_id, "device_guid": device_guid,
            "app_id": device.app_id, "timestamp_ms": int(now_ms - 60_000 + index * 20_000),
            "nonce": _ident(rng, "n_", 16), "seq": index, "consent": consent, "environment": env,
            "touch_events": touch_part, "key_events": key_part, "ui_events": ui_part,
            "sensor_data": sensor_part, "user_id": user_id,
        }
        batches.append(device.sign(payload))

    evaluate = {
        "session_id": session_id, "user_id": user_id, "event_type": "FUNDS_TRANSFER",
        "request_id": _ident(rng, "req_", 12),
        "transaction_details": {"amount": 250000.0, "currency": "PKR",
                                "beneficiary_account": "PK36EXMP00992201029381",
                                "is_new_beneficiary": new_payee},
    }
    return {
        "scenario": scenario, "expected_at_least": EXPECTED_AT_LEAST[scenario],
        "expected_at_most": EXPECTED_AT_MOST.get(scenario, "BLOCK"),
        "session_id": session_id, "device": device, "batches": batches, "evaluate": evaluate,
    }


def _slice(sensors, a, b):
    out = {}
    for name, samples in sensors.items():
        n = len(samples)
        out[name] = samples[int(n * a): int(n * b)]
    return out


def build_dataset(now_ms, per_scenario=5):
    return [
        build_session(name, now_ms, seed)
        for name in SCENARIOS
        for seed in range(per_scenario)
    ]
