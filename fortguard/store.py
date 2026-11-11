"""In-memory session store. One process, no persistence: a stand-in for the sharded store in the PRD."""

import threading
import math
import time
from dataclasses import dataclass, field

from . import config, schema
from .incremental import FeatureState

ANY_FLAGS = (
    "is_rooted", "is_emulator", "has_hooking_framework", "active_remote_software", "vpn",
    "mock_location",
)
LATEST_FLAGS = ("active_call", "cellular_call", "screen_sharing")
# Facts from newer SDKs. Stored only when the app reports them, so an older app or an iPhone that cannot
# measure one shows "not reported" in the back office, never a false "no".
STICKY_FACTS = ("debugger_attached", "sim_changed", "keyboard_changed", "remote_access_installed",
                "developer_options", "unknown_accessibility_service")
LATEST_FACTS = ("roaming", "screen_reader")


class ReplayDetected(Exception):
    pass


class DeviceMismatch(Exception):
    pass


@dataclass
class Session:
    session_id: str
    device_guid: str
    created: float
    last_seen: float
    consent_behavioral: bool = False
    user_id: str = None
    integrity: str = None  # attestation level of the enrolled device, set by the server, never by the SDK
    env: dict = field(default_factory=dict)
    nonces: set = field(default_factory=set)
    touch: list = field(default_factory=list)
    keys: list = field(default_factory=list)
    ui: list = field(default_factory=list)
    accel: list = field(default_factory=list)
    gyro: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)  # name -> samples, for sensors not used in scoring
    fstate: object = None  # incremental feature state (incremental.FeatureState)
    owner_proved: bool = False  # a batch in this session carried a valid owner proof
    ip: str = None  # client address of the latest batch, from the socket or the trusted proxy
    ip_changes: int = 0  # times the address changed within the session (mobile handovers do this too)
    location: dict = None  # latest approximate location the app sent, with the time of its fix
    location_jump: bool = False  # sticky: the phone was somewhere physically impossible within this session

    def event_count(self):
        return (len(self.touch) + len(self.keys) + len(self.ui) + len(self.accel) + len(self.gyro)
                + sum(len(v) for v in self.extra.values()))


class SessionStore:
    def __init__(self, clock=time.time, ttl_s=config.SESSION_TTL_S):
        self.clock = clock
        self.ttl_s = ttl_s
        self._sessions = {}
        self.lock = threading.RLock()
        self._lock = self.lock

    def count(self):
        with self._lock:
            return len(self._sessions)

    def get(self, session_id):
        now = self.clock()
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if now - session.last_seen > self.ttl_s:
                del self._sessions[session_id]
                return None
            return session

    def ingest(self, p, integrity=None, owner_proved=False, ip=None):
        """Store one validated, signature-checked batch. Returns counts of what was kept."""
        now = self.clock()
        with self._lock:
            session = self._sessions.get(p["session_id"])
            if session is not None and now - session.last_seen > self.ttl_s:
                del self._sessions[p["session_id"]]
                session = None
            is_new = session is None
            if is_new:
                session = Session(p["session_id"], p["device_guid"], now, now)
            if session.device_guid != p["device_guid"]:
                raise DeviceMismatch()
            if p["nonce"] in session.nonces:
                raise ReplayDetected()

            session.nonces.add(p["nonce"])
            session.last_seen = now
            session.integrity = integrity
            self._merge_env(session, p["environment"])
            if ip is not None:
                _note_ip(session, ip)
            if "location" in p["environment"]:
                _note_location(session, p["environment"]["location"], p["timestamp_ms"])

            consent = bool(p.get("consent", {}).get("behavioral", False))
            session.consent_behavioral = consent
            kept = {"touch": 0, "key": 0, "ui": 0, "sensor": 0}
            # Defense in depth: without consent the server drops behavioral data, whatever the SDK sent.
            if consent:
                room = max(0, config.MAX_EVENTS_PER_SESSION - session.event_count())
                sensors = p.get("sensor_data", {})
                added = {}
                for name, bucket, attr in (
                    ("touch_events", "touch", "touch"),
                    ("key_events", "key", "keys"),
                    ("ui_events", "ui", "ui"),
                ):
                    items = p.get(name, [])[:room]
                    getattr(session, attr).extend(items)
                    added[attr] = items
                    kept[bucket] = len(items)
                    room -= len(items)
                for name, attr in (("accelerometer", "accel"), ("gyroscope", "gyro")):
                    items = sensors.get(name, [])[:room]
                    getattr(session, attr).extend(items)
                    added[attr] = items
                    kept["sensor"] += len(items)
                    room -= len(items)
                for name in config.EXTRA_SENSORS:
                    items = sensors.get(name, [])[:room]
                    if items:
                        session.extra.setdefault(name, []).extend(items)
                    kept["sensor"] += len(items)
                    room -= len(items)
                if session.fstate is None:
                    session.fstate = FeatureState()
                session.fstate.update(added["touch"], added["keys"], added["ui"], added["accel"], added["gyro"])

            if owner_proved:
                session.owner_proved = True
            if is_new:
                self._sessions[session.session_id] = session
            return kept

    @staticmethod
    def _merge_env(session, env):
        for name in ANY_FLAGS:
            session.env[name] = bool(session.env.get(name, False) or env.get(name, False))
        for name in LATEST_FLAGS:
            session.env[name] = bool(env.get(name, False))
        for name in ("os", "os_version"):
            if name in env:
                session.env[name] = env[name]
        for name in STICKY_FACTS:
            if name in env:
                session.env[name] = bool(session.env.get(name, False) or env[name])
        for name in LATEST_FACTS + ("charging", "network_type", "locale", "timezone", "device_model",
                                    "security_patch", "carrier", "call_direction") + tuple(schema.ENV_EXTRA_NUMBERS):
            if name in env:
                session.env[name] = env[name]


def _note_ip(session, ip):
    if session.ip is not None and ip != session.ip:
        session.ip_changes += 1
    session.ip = ip


def _distance_km(a, b):
    """Great-circle distance between two (lat, lng) points, in kilometres."""
    lat1, lng1, lat2, lng2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lng2 - lng1) / 2) ** 2
    return 2 * 6371.0 * math.asin(min(1.0, math.sqrt(h)))


def _note_location(session, loc, batch_ts_ms):
    """Keeps the latest fix and marks a jump if the phone covered more ground than is physically possible.

    The fix time is the batch time minus how old the fix was, so a stale last-known location is not
    compared with a fresh one as if both were current.
    """
    fix_ts = batch_ts_ms - int(float(loc.get("fix_age_s", 0)) * 1000)
    here = {"lat": float(loc["lat"]), "lng": float(loc["lng"]), "accuracy_m": loc.get("accuracy_m"), "fix_ts_ms": fix_ts}
    prev = session.location
    if prev is not None and fix_ts > prev["fix_ts_ms"]:
        km = _distance_km((prev["lat"], prev["lng"]), (here["lat"], here["lng"]))
        hours = (fix_ts - prev["fix_ts_ms"]) / 3_600_000
        if km >= config.LOCATION_JUMP_MIN_KM and km / max(hours, 1e-9) > config.LOCATION_MAX_KMH:
            session.location_jump = True
    session.location = here
