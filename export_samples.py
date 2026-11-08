"""Write sample payloads to samples/: enrollment, signed telemetry, evaluate request and response.

    python export_samples.py

Reproducible: fixed clock, deterministic challenges, and deterministic ECDSA signatures from the
simulated device. Everything is signed with development keys and means nothing outside this repo.
"""

import itertools
import json
import pathlib

from fortguard.app import create_app
from fortguard.client import InProcessTransport, enroll_device
from fortguard.devices import DeviceRegistry
from fortguard.generator import build_session

FIXED_NOW = 1_800_000_000.0  # fixed server clock, so the timestamps in the samples line up


def short(batch, device):
    """Keep sample files readable: first few events of each kind only, then re-sign."""
    out = json.loads(json.dumps(batch))
    out["touch_events"] = out["touch_events"][:6]
    out["key_events"] = out["key_events"][:6]
    for name in ("accelerometer", "gyroscope"):
        out["sensor_data"][name] = out["sensor_data"][name][:3]
    return device.sign(out)


def write(root, name, data):
    (root / name).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def main():
    root = pathlib.Path(__file__).parent / "samples"
    root.mkdir(exist_ok=True)
    counter = itertools.count(1)
    registry = DeviceRegistry(clock=lambda: FIXED_NOW, randbytes=lambda n: next(counter).to_bytes(n, "big"))
    app = create_app(clock=lambda: FIXED_NOW, registry=registry)
    transport = InProcessTransport(app)
    now_ms = int(FIXED_NOW * 1000)

    for name in ("genuine", "coached_scam"):
        session = build_session(name, now_ms, seed=1)
        device = session["device"]
        challenge = registry.issue_challenge()  # same value the enroll call below would consume
        enroll_request = device.enrollment_request(challenge, now_ms)
        status, enrolled = transport.post("/v1/devices/enroll", enroll_request)
        assert status == 201, enrolled
        for batch in session["batches"]:
            assert transport.post("/v1/telemetry/stream", batch)[0] == 202
        status, body = transport.post("/v1/risk/evaluate", session["evaluate"], auth=True)
        body["latency_ms"] = 0.0  # a live measurement; pinned so the sample files are reproducible
        write(root, f"{name}.enroll_request.json", enroll_request)
        write(root, f"{name}.telemetry.json", short(session["batches"][0], device))
        write(root, f"{name}.evaluate_request.json", session["evaluate"])
        write(root, f"{name}.evaluate_response.json", body)
        print(name, status, body["risk_score"], body["risk_level"], body["reason_codes"])
    print("telemetry samples are shortened and re-signed, so they still verify against the enrolled key")


if __name__ == "__main__":
    main()
