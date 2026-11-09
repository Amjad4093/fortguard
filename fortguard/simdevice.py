"""A simulated phone: it owns a private key, asks for attestation and signs its own batches.

Stands in for the mobile SDK in tests and the demo. A real device generates the key in hardware and
the attestation comes from Google or Apple, not from `DEV_AUTHORITY`.
"""

import random

from .attestation import DEV_AUTHORITY
from .signing import key_from_seed, key_sha256, public_key_to_b64, sign_payload

DEFAULT_APP_ID = "com.example.mobilebank"


class SimDevice:
    def __init__(self, seed, app_id=DEFAULT_APP_ID, platform="Android", authority=DEV_AUTHORITY):
        rng = random.Random(f"device:{seed}")
        self.device_guid = "dev_" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12))
        self.app_id = app_id
        self.platform = platform
        self.authority = authority
        self._private = key_from_seed(f"simdevice:{seed}".encode())
        self.public_key = self._private.public_key()

    @property
    def public_key_b64(self):
        return public_key_to_b64(self.public_key)

    def enrollment_request(self, challenge, now_ms, level="STRONG"):
        token = self.authority.issue(
            device_guid=self.device_guid, app_id=self.app_id, platform=self.platform,
            challenge=challenge, key_sha256=key_sha256(self.public_key), level=level, now_ms=now_ms,
        )
        return {
            "device_guid": self.device_guid, "app_id": self.app_id, "platform": self.platform,
            "public_key": self.public_key_b64, "challenge": challenge, "attestation": token,
        }

    def sign(self, payload):
        payload = {k: v for k, v in payload.items() if k != "signature"}
        payload["signature"] = sign_payload(payload, self._private)
        return payload
