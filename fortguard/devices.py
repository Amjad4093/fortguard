"""In-memory device registry and one-time enrollment challenges.

One process, no persistence, like the session store. Production keeps devices in a database and
challenges in the shared fast store, both partitioned by device.
"""

import secrets
import threading
import time
from dataclasses import dataclass

from . import config
from .signing import b64e, key_sha256, public_key_to_b64

ACTIVE, REVOKED = "ACTIVE", "REVOKED"


@dataclass
class Device:
    device_guid: str
    app_id: str
    platform: str
    key: object
    key_sha256: str
    integrity: str
    enrolled_at: float
    status: str = ACTIVE
    key_version: int = 1

    @property
    def public_key_b64(self):
        return public_key_to_b64(self.key)


class DeviceRegistry:
    def __init__(self, clock=time.time, randbytes=secrets.token_bytes):
        self.clock = clock
        self._randbytes = randbytes
        self._devices = {}
        self._challenges = {}
        self._lock = threading.Lock()

    def issue_challenge(self):
        challenge = b64e(self._randbytes(32))
        now = self.clock()
        with self._lock:
            if len(self._challenges) >= config.MAX_CHALLENGES:
                for old in [c for c, expiry in self._challenges.items() if expiry < now]:
                    del self._challenges[old]
                if len(self._challenges) >= config.MAX_CHALLENGES:
                    return None
            self._challenges[challenge] = now + config.CHALLENGE_TTL_S
        return challenge

    def consume_challenge(self, challenge):
        """True once per issued, unexpired challenge. A failed enrollment still burns it."""
        with self._lock:
            expiry = self._challenges.pop(challenge, None)
        return expiry is not None and expiry >= self.clock()

    def get(self, device_guid):
        with self._lock:
            return self._devices.get(device_guid)

    def enroll(self, device_guid, app_id, platform, key, integrity):
        with self._lock:
            existing = self._devices.get(device_guid)
            version = existing.key_version + 1 if existing and existing.key_sha256 != key_sha256(key) else (
                existing.key_version if existing else 1
            )
            device = Device(device_guid, app_id, platform, key, key_sha256(key), integrity,
                            self.clock(), ACTIVE, version)
            self._devices[device_guid] = device
            return device

    def all(self):
        with self._lock:
            return list(self._devices.values())

    def revoke(self, device_guid):
        with self._lock:
            device = self._devices.get(device_guid)
            if device is None:
                return False
            device.status = REVOKED
            return True
