"""Strict validation of SDK telemetry and risk requests.

Privacy rule (BRD FR-SDK-001, NFR-003): no typed characters ever reach the server. Key and UI events
may carry only an event type, a timestamp and a field name from a fixed list. Any other key, and any
field name outside the list, is refused with code `forbidden_field`, so free text cannot be smuggled
in.
"""

import math
import re

from . import config

ID_RE = re.compile(r"^[A-Za-z0-9_\-]{8,64}$")
VERSION_RE = re.compile(r"^[0-9A-Za-z.\-_ ]{1,32}$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")

TOP_ALLOWED = {
    "session_id", "device_guid", "app_id", "timestamp_ms", "nonce", "seq", "consent",
    "environment", "touch_events", "key_events", "ui_events", "sensor_data", "signature", "owner_proof", "user_id", "customer_name",
}
TOP_REQUIRED = ("session_id", "device_guid", "app_id", "timestamp_ms", "nonce", "environment")

ENV_BOOLS = (
    "is_rooted", "is_emulator", "has_hooking_framework", "active_remote_software",
    "screen_sharing", "active_call", "cellular_call", "vpn", "mock_location",
    # Facts added for parity with the platform team's signal catalogue. Only two are scored
    # (debugger_attached, sim_changed); the rest are recorded and shown, never a reason on their own.
    "debugger_attached", "developer_options", "screen_reader", "unknown_accessibility_service",
    "remote_access_installed", "roaming", "sim_changed", "keyboard_changed",
    "hotspot",   # the Wi-Fi looks like another phone's hotspot (a metered Wi-Fi network). Recorded only.
)
ENV_EXTRA_NUMBERS = {  # name: (low, high, integer?)
    "battery_level": (0, 100, True),
    "network_changes": (0, 100000, True),
    "screen_width": (1, 10000, True),
    "screen_height": (1, 10000, True),
    "density": (0.5, 6.0, False),
    "app_install_age_days": (0, 36500, True),
    "free_storage_mb": (0, 10_000_000, True),
    "font_scale": (0.2, 5.0, False),
    "call_seconds": (0, 86_400, True),          # how long the current phone call has lasted
    "background_switches": (0, 100_000, True),  # times the app left the foreground since it started
    "screens_visited": (0, 100_000, True),
    "tz_offset_minutes": (-900, 900, True),
}
CALL_DIRECTIONS = ("incoming", "outgoing", "unknown")
SECURITY_PATCH_RE = re.compile(r"^20\d{2}-\d{2}-\d{2}$")   # Android security patch level, e.g. 2026-09-05
CARRIER_RE = re.compile(r"^\d{5,6}$")                       # mobile country code + network code, digits only
DEVICE_MODEL_RE = re.compile(r"^[A-Za-z0-9 _\-.()/+]{1,80}$")  # e.g. "Pixel 8", "SM-S921B"
CUSTOMER_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
LOCALE_RE = re.compile(r"^[A-Za-z]{2,8}([_\-][A-Za-z0-9]{2,8})?$")
TIMEZONE_RE = re.compile(r"^[A-Za-z0-9_+\-/]{1,64}$")
ENV_ALLOWED = (set(ENV_BOOLS) | {"os", "os_version", "device_model", "charging", "network_type", "locale", "timezone", "location",
                                 "security_patch", "carrier", "call_direction"}
               | set(ENV_EXTRA_NUMBERS))

TOUCH_TYPES = {"DOWN", "MOVE", "UP"}
KEY_TYPES = {"DOWN", "UP"}
UI_TYPES = {"FOCUS", "PASTE", "SUBMIT", "AUTOFILL"}  # AUTOFILL: the system filled the field, nobody typed
FIELDS = {"username", "password", "otp", "beneficiary_account", "amount", "other"}

# tdx, tdy: where a touch-down landed inside the control it hit, from -1 (left or top edge) through 0
# (the centre) to 1. Sent on DOWN only, and only when the SDK found the control.
TOUCH_KEYS = {"event_type", "x", "y", "pressure", "size", "timestamp_ms", "tdx", "tdy"}
KEY_KEYS = {"event_type", "ts", "field", "inserted", "deleted"}  # inserted/deleted: character counts only
UI_KEYS = {"event_type", "field", "ts"}
SENSOR_KEYS = {"x", "y", "z", "ts"}


class ValidationFailure(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _fail(code, message, status=400):
    raise ValidationFailure(status, code, message)


def _num(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _need_num(value, name, low=None, high=None):
    if not _num(value):
        _fail("invalid_request", f"{name} must be a number")
    if low is not None and value < low:
        _fail("invalid_request", f"{name} is out of range")
    if high is not None and value > high:
        _fail("invalid_request", f"{name} is out of range")


def _need_id(value, name):
    if not isinstance(value, str) or not ID_RE.match(value):
        _fail("invalid_request", f"{name} must be 8 to 64 letters, digits, underscore or dash")


def _need_list(payload, name, limit):
    items = payload.get(name, [])
    if not isinstance(items, list):
        _fail("invalid_request", f"{name} must be a list")
    if len(items) > limit:
        _fail("batch_too_large", f"{name} has more than {limit} items", status=413)
    return items


def validate_telemetry(p):
    """Raise ValidationFailure on the first problem. Return the payload when it is valid."""
    if not isinstance(p, dict):
        _fail("invalid_request", "body must be a JSON object")
    unknown = set(p) - TOP_ALLOWED
    if unknown:
        _fail("unknown_field", f"unknown fields: {sorted(unknown)}")
    for name in TOP_REQUIRED:
        if name not in p:
            _fail("invalid_request", f"missing field {name}")

    _need_id(p["session_id"], "session_id")
    _need_id(p["device_guid"], "device_guid")
    _need_id(p["nonce"], "nonce")
    if not isinstance(p["app_id"], str) or not 1 <= len(p["app_id"]) <= 128:
        _fail("invalid_request", "app_id must be a string of 1 to 128 characters")
    _need_num(p["timestamp_ms"], "timestamp_ms", low=1)
    if "seq" in p:
        _need_num(p["seq"], "seq", low=0)

    consent = p.get("consent", {})
    if not isinstance(consent, dict) or set(consent) - {"behavioral", "location", "texts"}:
        _fail("invalid_request", "consent may only contain behavioral, location and texts")
    for name in ("behavioral", "location"):
        if name in consent and not isinstance(consent[name], bool):
            _fail("invalid_request", f"consent.{name} must be true or false")
    # Which published wording the customer accepted, per group: {"behavioural": {"lang": "en", "version": 2}}.
    texts = consent.get("texts", {})
    if not isinstance(texts, dict) or set(texts) - {"behavioural", "location"}:
        _fail("invalid_request", "consent.texts may only name the behavioural and location groups")
    for group, accepted in texts.items():
        if (not isinstance(accepted, dict) or set(accepted) != {"lang", "version"}
                or not isinstance(accepted["lang"], str) or not re.fullmatch(r"[a-z]{2,3}(-[A-Z]{2})?", accepted["lang"])
                or isinstance(accepted["version"], bool) or not isinstance(accepted["version"], int)
                or not 1 <= accepted["version"] <= 100_000):
            _fail("invalid_request", f"consent.texts.{group} needs a lang code and a whole-number version")

    if "user_id" in p:  # optional: the customer id the app uses, so usage can be recorded per customer
        if not isinstance(p["user_id"], str) or not CUSTOMER_ID_RE.fullmatch(p["user_id"]):
            _fail("invalid_request", "user_id must be 1-64 letters, digits, _ or -")
    if "customer_name" in p:  # optional: the customer's name, as typed in the app
        name = p["customer_name"]
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or any(ord(c) < 32 for c in name):
            _fail("invalid_request", "customer_name must be plain text, 1-80 characters")
    if "owner_proof" in p:  # optional: a batch recorded during an owner enrolment window
        proof = p["owner_proof"]
        if not isinstance(proof, dict) or set(proof) != {"public_key", "signature"} or not all(
                isinstance(proof[k], str) and 1 <= len(proof[k]) <= 1024 for k in proof):
            _fail("invalid_request", "owner_proof must hold public_key and signature text")
    env = p["environment"]
    if not isinstance(env, dict):
        _fail("invalid_request", "environment must be an object")
    extra = set(env) - ENV_ALLOWED
    if extra:
        _fail("unknown_field", f"unknown environment fields: {sorted(extra)}")
    for name in ENV_BOOLS:
        if name in env and not isinstance(env[name], bool):
            _fail("invalid_request", f"environment.{name} must be true or false")
    if "os" in env and env["os"] not in config.PLATFORMS:
        _fail("invalid_request", f"environment.os must be one of {list(config.PLATFORMS)}")
    if "os_version" in env and (
        not isinstance(env["os_version"], str) or not VERSION_RE.match(env["os_version"])
    ):
        _fail("invalid_request", "environment.os_version is not a valid version string")
    if "device_model" in env and (not isinstance(env["device_model"], str) or not DEVICE_MODEL_RE.match(env["device_model"])):
        _fail("invalid_request", "environment.device_model is not a valid model name")
    if "charging" in env and not isinstance(env["charging"], bool):
        _fail("invalid_request", "environment.charging must be true or false")
    for name, (low, high, integer) in ENV_EXTRA_NUMBERS.items():
        if name in env:
            value = env[name]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                _fail("invalid_request", f"environment.{name} must be a number")
            if integer and not float(value).is_integer():
                _fail("invalid_request", f"environment.{name} must be a whole number")
            if not low <= value <= high:
                _fail("invalid_request", f"environment.{name} is out of range")
    if "location" in env:  # optional, only when the customer shared their approximate location
        loc = env["location"]
        if not isinstance(loc, dict) or set(loc) - {"lat", "lng", "accuracy_m", "fix_age_s"}:
            _fail("invalid_request", "environment.location must hold lat, lng and optionally accuracy_m, fix_age_s")
        for key, low, high in (("lat", -90, 90), ("lng", -180, 180), ("accuracy_m", 0, 100000), ("fix_age_s", 0, 86400)):
            if key not in loc and key in ("lat", "lng"):
                _fail("invalid_request", f"environment.location.{key} is required")
            if key in loc and (isinstance(loc[key], bool) or not isinstance(loc[key], (int, float))
                               or not low <= loc[key] <= high):
                _fail("invalid_request", f"environment.location.{key} is out of range")
    if "network_type" in env and env["network_type"] not in config.NETWORK_TYPES:
        _fail("invalid_request", f"environment.network_type must be one of {list(config.NETWORK_TYPES)}")
    if "locale" in env and (not isinstance(env["locale"], str) or not LOCALE_RE.match(env["locale"])):
        _fail("invalid_request", "environment.locale is not a valid locale tag")
    if "timezone" in env and (not isinstance(env["timezone"], str) or not TIMEZONE_RE.match(env["timezone"])):
        _fail("invalid_request", "environment.timezone is not a valid zone name")
    if "security_patch" in env and (not isinstance(env["security_patch"], str) or not SECURITY_PATCH_RE.match(env["security_patch"])):
        _fail("invalid_request", "environment.security_patch must look like 2026-09-05")
    if "carrier" in env and (not isinstance(env["carrier"], str) or not CARRIER_RE.match(env["carrier"])):
        _fail("invalid_request", "environment.carrier must be 5 or 6 digits")
    if "call_direction" in env and env["call_direction"] not in CALL_DIRECTIONS:
        _fail("invalid_request", f"environment.call_direction must be one of {list(CALL_DIRECTIONS)}")

    for e in _need_list(p, "touch_events", config.MAX_TOUCH_PER_BATCH):
        if not isinstance(e, dict) or set(e) - TOUCH_KEYS:
            _fail("unknown_field", "touch events may only carry " + ", ".join(sorted(TOUCH_KEYS)))
        if e.get("event_type") not in TOUCH_TYPES:
            _fail("invalid_request", "touch event_type must be DOWN, MOVE or UP")
        for name in ("x", "y", "timestamp_ms"):
            if name not in e:
                _fail("invalid_request", f"touch event is missing {name}")
        _need_num(e["x"], "touch x", -10000, 10000)
        _need_num(e["y"], "touch y", -10000, 10000)
        _need_num(e["timestamp_ms"], "touch timestamp_ms", 1)
        if "pressure" in e:
            _need_num(e["pressure"], "touch pressure", 0, 2)
        if "size" in e:
            _need_num(e["size"], "touch size", 0, 1000)
        if ("tdx" in e) != ("tdy" in e):
            _fail("invalid_request", "touch tdx and tdy come together")
        if "tdx" in e:
            _need_num(e["tdx"], "touch tdx", -1, 1)
            _need_num(e["tdy"], "touch tdy", -1, 1)

    for e in _need_list(p, "key_events", config.MAX_KEYS_PER_BATCH):
        _check_event(e, "key", KEY_KEYS, KEY_TYPES)
        for name in ("inserted", "deleted"):
            if name in e:
                _need_num(e[name], f"key {name}", 0, 1000)
    for e in _need_list(p, "ui_events", config.MAX_UI_PER_BATCH):
        _check_event(e, "ui", UI_KEYS, UI_TYPES)

    sensors = p.get("sensor_data", {})
    if not isinstance(sensors, dict) or set(sensors) - set(config.SENSOR_NAMES):
        _fail("invalid_request", "sensor_data may only contain: " + ", ".join(config.SENSOR_NAMES))
    for name in config.SENSOR_NAMES:
        samples = sensors.get(name, [])
        if not isinstance(samples, list):
            _fail("invalid_request", f"{name} must be a list")
        if len(samples) > config.MAX_SENSOR_PER_BATCH:
            _fail("batch_too_large", f"{name} has too many samples", status=413)
        for s in samples:
            if not isinstance(s, dict) or set(s) != SENSOR_KEYS:
                _fail("invalid_request", f"{name} samples need exactly x, y, z and ts")
            for axis in ("x", "y", "z"):
                _need_num(s[axis], f"{name} {axis}", -1000, 1000)
            _need_num(s["ts"], f"{name} ts", 1)
    return p


def _check_event(e, kind, allowed_keys, allowed_types):
    if not isinstance(e, dict):
        _fail("invalid_request", f"{kind} events must be objects")
    if set(e) - allowed_keys:
        _fail(
            "forbidden_field",
            f"{kind} events may only carry {sorted(allowed_keys)}; typed content is never accepted",
            status=422,
        )
    if e.get("event_type") not in allowed_types:
        _fail("invalid_request", f"{kind} event_type must be one of {sorted(allowed_types)}")
    if "ts" not in e:
        _fail("invalid_request", f"{kind} event is missing ts")
    _need_num(e["ts"], f"{kind} ts", 1)
    if "field" in e and e["field"] not in FIELDS:
        _fail(
            "forbidden_field",
            f"{kind} event field must be one of {sorted(FIELDS)}",
            status=422,
        )


ENROLL_ALLOWED = {"device_guid", "app_id", "platform", "public_key", "challenge", "attestation"}


def validate_enroll(p):
    if not isinstance(p, dict):
        _fail("invalid_request", "body must be a JSON object")
    unknown = set(p) - ENROLL_ALLOWED
    if unknown:
        _fail("unknown_field", f"unknown fields: {sorted(unknown)}")
    for name in sorted(ENROLL_ALLOWED):
        if name not in p:
            _fail("invalid_request", f"missing field {name}")
    _need_id(p["device_guid"], "device_guid")
    if not isinstance(p["app_id"], str) or not 1 <= len(p["app_id"]) <= 128:
        _fail("invalid_request", "app_id must be a string of 1 to 128 characters")
    if p["platform"] not in config.PLATFORMS:
        _fail("invalid_request", f"platform must be one of {list(config.PLATFORMS)}")
    for name, limit in (("public_key", 256), ("challenge", 128), ("attestation", 8192)):
        if not isinstance(p[name], str) or not 1 <= len(p[name]) <= limit:
            _fail("invalid_request", f"{name} must be a string of 1 to {limit} characters")
    return p


EVAL_ALLOWED = {"session_id", "user_id", "event_type", "transaction_details", "request_id", "allow_degraded"}
TX_ALLOWED = {"amount", "currency", "beneficiary_account", "is_new_beneficiary"}


def validate_evaluate(p):
    if not isinstance(p, dict):
        _fail("invalid_request", "body must be a JSON object")
    unknown = set(p) - EVAL_ALLOWED
    if unknown:
        _fail("unknown_field", f"unknown fields: {sorted(unknown)}")
    for name in ("session_id", "user_id", "event_type"):
        if name not in p:
            _fail("invalid_request", f"missing field {name}")
    _need_id(p["session_id"], "session_id")
    if not isinstance(p["user_id"], str) or not 1 <= len(p["user_id"]) <= 64:
        _fail("invalid_request", "user_id must be a string of 1 to 64 characters")
    if p["event_type"] not in config.EVENT_TYPES:
        _fail("invalid_request", f"event_type must be one of {list(config.EVENT_TYPES)}")
    if "request_id" in p:
        _need_id(p["request_id"], "request_id")
    if "allow_degraded" in p and not isinstance(p["allow_degraded"], bool):
        _fail("invalid_request", "allow_degraded must be true or false")

    tx = p.get("transaction_details")
    if p["event_type"] in config.PAYMENT_EVENTS and tx is None:
        _fail("invalid_request", "transaction_details is required for this event_type")
    if tx is not None:
        if not isinstance(tx, dict) or set(tx) - TX_ALLOWED:
            _fail("unknown_field", f"transaction_details may only carry {sorted(TX_ALLOWED)}")
        acct = tx.get("beneficiary_account")
        if acct is not None and (not isinstance(acct, str) or not 8 <= len(acct) <= 40):
            _fail("invalid_request", "beneficiary_account must be a string of 8 to 40 characters")
        if p["event_type"] in config.PAYMENT_EVENTS and acct is None:
            _fail("invalid_request", "beneficiary_account is required for this event_type")
        if p["event_type"] == "FUNDS_TRANSFER":
            _need_num(tx.get("amount"), "amount", 0)
            if not isinstance(tx.get("currency"), str) or not CURRENCY_RE.match(tx["currency"]):
                _fail("invalid_request", "currency must be a 3-letter code")
        if "is_new_beneficiary" in tx and not isinstance(tx["is_new_beneficiary"], bool):
            _fail("invalid_request", "is_new_beneficiary must be true or false")
    return p


FEEDBACK_ALLOWED = {"session_id", "label", "source", "note"}
FEEDBACK_LABELS = ("FRAUD", "GENUINE")


def validate_feedback(p):
    if not isinstance(p, dict):
        _fail("invalid_request", "body must be a JSON object")
    unknown = set(p) - FEEDBACK_ALLOWED
    if unknown:
        _fail("unknown_field", f"unknown fields: {sorted(unknown)}")
    if "session_id" not in p or "label" not in p:
        _fail("invalid_request", "session_id and label are required")
    _need_id(p["session_id"], "session_id")
    if p["label"] not in FEEDBACK_LABELS:
        _fail("invalid_request", f"label must be one of {list(FEEDBACK_LABELS)}")
    for name, limit in (("source", 64), ("note", 500)):
        if name in p and (not isinstance(p[name], str) or len(p[name]) > limit):
            _fail("invalid_request", f"{name} must be a string of at most {limit} characters")
    return p
