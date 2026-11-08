"""A stand-in for the mobile SDK uplink, used by the demo and the tests.

It posts the signed batches a session produced, then asks for the decision the way the bank
backend would. Two transports share one interface: real HTTP, or an in-process Flask test client.
"""

import json

from .app import DEV_API_KEY


class HttpTransport:
    def __init__(self, base_url, api_key=DEV_API_KEY):
        import requests

        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._requests = requests

    def post(self, path, payload, auth=False):
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["X-API-Key"] = self.api_key
        r = self._requests.post(self.base_url + path, data=json.dumps(payload), headers=headers, timeout=10)
        return r.status_code, r.json()


class InProcessTransport:
    def __init__(self, app, api_key=DEV_API_KEY):
        self.client = app.test_client()
        self.api_key = api_key

    def post(self, path, payload, auth=False):
        headers = {"X-API-Key": self.api_key} if auth else {}
        r = self.client.post(path, data=json.dumps(payload), content_type="application/json", headers=headers)
        return r.status_code, r.get_json()


def enroll_device(transport, device, now_ms, level="STRONG"):
    """Challenge, then enroll. Returns (status, body) of the enroll call."""
    status, body = transport.post("/v1/devices/challenge", {})
    if status != 201:
        raise RuntimeError(f"challenge refused: {status} {body}")
    return transport.post("/v1/devices/enroll", device.enrollment_request(body["challenge"], now_ms, level))


def run_session(transport, session, now_ms=None, level="STRONG", enroll=True):
    """Enroll the device, send every telemetry batch, then evaluate. Returns (status, body)."""
    if enroll:
        now_ms = now_ms if now_ms is not None else session["batches"][0]["timestamp_ms"] + 60_000
        status, body = enroll_device(transport, session["device"], now_ms, level)
        if status != 201:
            raise RuntimeError(f"enrollment rejected: {status} {body}")
    for batch in session["batches"]:
        status, body = transport.post("/v1/telemetry/stream", batch)
        if status != 202:
            raise RuntimeError(f"telemetry rejected: {status} {body}")
    return transport.post("/v1/risk/evaluate", session["evaluate"], auth=True)
