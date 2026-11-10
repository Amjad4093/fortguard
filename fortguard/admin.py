"""Analyst and test-harness endpoints.

Always on (X-API-Key required):
    GET  /portal                        analyst portal page
    GET  /v1/admin/decisions            recent decisions, newest first, with counts
    GET  /v1/admin/devices              enrolled devices

Only when the app runs in dev mode (`--dev` or FORTGUARD_DEV_MODE=1), otherwise 404:
    GET  /phone                         browser test client with real touch and motion capture
    POST /v1/dev/attest                 mints a SIMULATED attestation token (stands in for Google/Apple)
    GET  /v1/dev/scenarios              synthetic scenario names
    POST /v1/dev/simulate               run one synthetic scenario end to end

The decision log keeps the last 4 digits of the beneficiary account, never the full number.
"""

import pathlib
import threading
import time
from collections import Counter, deque

from flask import abort, current_app, jsonify, request, send_from_directory

from . import config
from .attestation import DEV_AUTHORITY, LEVELS
from .features import typing_totals
from .schema import ENV_BOOLS, ENV_EXTRA_NUMBERS, ID_RE, ValidationFailure

WEB_DIR = pathlib.Path(__file__).parent / "web"
MAX_DECISIONS = 500
GRID_COLS, GRID_ROWS = 8, 14  # touch heatmap resolution, stored as counts per cell
# Device facts the portal may show. Locale, timezone and anything free-form are deliberately left out.
ENV_SHOWN = tuple(ENV_BOOLS) + ("os", "os_version", "device_model", "network_type", "charging") + tuple(ENV_EXTRA_NUMBERS)
# Signal keys recorded in "captured": touch, keys, ui, the two base sensors, and every extra sensor.
SIGNAL_KEYS = ("touch", "keys", "ui", "accelerometer", "gyroscope") + tuple(config.EXTRA_SENSORS)


def captured_counts(session):
    """How many samples each signal delivered in this session. Numbers only, zero included.

    A degraded decision has no telemetry at all, so every count is zero.
    """
    counts = {name: len(getattr(session, attr, None) or [])
              for name, attr in (("touch", "touch"), ("keys", "keys"), ("ui", "ui"),
                                 ("accelerometer", "accel"), ("gyroscope", "gyro"))}
    extra = getattr(session, "extra", None) or {}
    for name in config.EXTRA_SENSORS:
        counts[name] = len(extra.get(name) or [])
    return counts


def touch_grid(session):
    """Touch positions binned onto a coarse grid, normalised to the screen when it is known."""
    points = [(e["x"], e["y"]) for e in (getattr(session, "touch", None) or []) if "x" in e and "y" in e]
    if not points:
        return None
    env = getattr(session, "env", None) or {}
    width = env.get("screen_width") or max(x for x, _ in points) or 1
    height = env.get("screen_height") or max(y for _, y in points) or 1
    grid = [[0] * GRID_COLS for _ in range(GRID_ROWS)]
    for x, y in points:
        col = min(GRID_COLS - 1, max(0, int(x / width * GRID_COLS)))
        row = min(GRID_ROWS - 1, max(0, int(y / height * GRID_ROWS)))
        grid[row][col] += 1
    return grid


def _typing(session):
    inserted, deleted, active_ms = typing_totals(getattr(session, "keys", None) or [])
    return int(inserted), int(deleted), int(round(active_ms))


def _network_of(session):
    """Network facts for the decision: client address, its changes, and the shared location rounded to about 1 km."""
    loc = getattr(session, "location", None)
    return {
        "ip": getattr(session, "ip", None),
        "ip_changes": getattr(session, "ip_changes", 0),
        "location": ({"lat": round(loc["lat"], 2), "lng": round(loc["lng"], 2),
                      "accuracy_m": loc.get("accuracy_m")} if loc else None),
        "location_jump": bool(getattr(session, "location_jump", False)),
    }


class DecisionLog:
    """Bounded in-memory log of evaluate results, for the portal. Not an audit log."""

    def __init__(self, maxlen=MAX_DECISIONS):
        self._items = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def record(self, body, session, result, now_s, features=None):
        tx = body.get("transaction_details") or {}
        env = getattr(session, "env", None) or {}
        account = tx.get("beneficiary_account")
        entry = {
            "time_ms": int(now_s * 1000),
            "session_id": body["session_id"],
            "user_id": body["user_id"],
            "device_guid": session.device_guid,
            "event_type": body["event_type"],
            "amount": tx.get("amount"),
            "currency": tx.get("currency"),
            "beneficiary_last4": account[-4:] if isinstance(account, str) else None,
            "is_new_beneficiary": bool(tx.get("is_new_beneficiary")),
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "action_recommended": result["action_recommended"],
            "reason_codes": result["reason_codes"],
            "score_breakdown": result["score_breakdown"],
            "threat_details": result["threat_details"],
            "signals_used": result["signals_used"],
            "device_integrity": session.integrity,
            "model_version": result["model_version"],
            "latency_ms": result.get("latency_ms"),
            "baseline": result.get("baseline"),
            # Numbers only: the behavioural measurements behind this decision, for the back office.
            "features": {k: round(float(v), 4) for k, v in (features or {}).items()
                         if isinstance(v, (int, float)) and not isinstance(v, bool)},
            "captured": captured_counts(session),
            "typing": dict(zip(("typed_chars", "corrected_chars", "active_ms"), _typing(session))),
            "touch_grid": touch_grid(session),
            "environment": {k: env[k] for k in ENV_SHOWN if k in env},
            "network": _network_of(session),
        }
        with self._lock:
            self._items.appendleft(entry)
        return entry

    def snapshot(self):
        with self._lock:
            return list(self._items)


def register(app, *, api_key, store, registry, decisions, clock, dev_mode):
    def need_key():
        if request.headers.get("X-API-Key") != api_key:
            raise ValidationFailure(401, "unauthorized", "missing or wrong X-API-Key")

    def need_dev():
        if not dev_mode:
            abort(404)

    @app.get("/portal")
    def portal():
        return send_from_directory(WEB_DIR, "portal.html")

    @app.get("/web/<path:name>")
    def web_asset(name):
        if name not in ("fgcore.js",):
            abort(404)
        return send_from_directory(WEB_DIR, name)

    @app.get("/v1/admin/decisions")
    def admin_decisions():
        need_key()
        items = decisions.snapshot()
        counts = Counter(item["risk_level"] for item in items)
        level = request.args.get("level")
        if level:
            items = [item for item in items if item["risk_level"] == level]
        try:
            limit = max(1, min(int(request.args.get("limit", 100)), MAX_DECISIONS))
        except ValueError:
            raise ValidationFailure(400, "invalid_request", "limit must be a number")
        return jsonify({
            "decisions": items[:limit],
            "counts": {"total": sum(counts.values()), "ALLOW": counts["ALLOW"],
                       "STEP_UP": counts["STEP_UP"], "BLOCK": counts["BLOCK"]},
            "dev_mode": dev_mode,
        })

    @app.get("/v1/admin/devices")
    def admin_devices():
        need_key()
        rows = [
            {"device_guid": d.device_guid, "app_id": d.app_id, "platform": d.platform,
             "integrity_level": d.integrity, "status": d.status, "key_version": d.key_version,
             "key_sha256": d.key_sha256[:16], "enrolled_at_ms": int(d.enrolled_at * 1000)}
            for d in registry.all()
        ]
        rows.sort(key=lambda r: -r["enrolled_at_ms"])
        return jsonify({"devices": rows})

    # --- Dev-only harness -----------------------------------------------------------------

    @app.get("/phone")
    def phone():
        need_dev()
        return send_from_directory(WEB_DIR, "phone.html")

    @app.post("/v1/dev/attest")
    def dev_attest():
        need_dev()
        from .signing import key_sha256, load_public_key

        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            raise ValidationFailure(400, "invalid_json", "body must be a JSON object")
        level = body.get("level", "STRONG")
        if level not in LEVELS:
            raise ValidationFailure(400, "invalid_request", f"level must be one of {list(LEVELS)}")
        if not isinstance(body.get("device_guid"), str) or not ID_RE.match(body["device_guid"]):
            raise ValidationFailure(400, "invalid_request", "device_guid is required")
        if not isinstance(body.get("challenge"), str) or not body["challenge"]:
            raise ValidationFailure(400, "invalid_request", "challenge is required")
        if body.get("platform") not in config.PLATFORMS or not isinstance(body.get("app_id"), str):
            raise ValidationFailure(400, "invalid_request", "platform and app_id are required")
        try:
            key = load_public_key(body.get("public_key", ""))
        except ValueError:
            raise ValidationFailure(400, "invalid_public_key", "public_key must be a base64url P-256 SPKI key")
        token = DEV_AUTHORITY.issue(
            device_guid=body["device_guid"], app_id=body["app_id"], platform=body["platform"],
            challenge=body["challenge"], key_sha256=key_sha256(key), level=level,
            now_ms=int(clock() * 1000),
        )
        return jsonify({"attestation": token, "note": "SIMULATED attestation, development only"})

    @app.get("/v1/dev/scenarios")
    def dev_scenarios():
        need_dev()
        need_key()
        from .generator import SCENARIOS

        return jsonify({"scenarios": list(SCENARIOS)})

    @app.post("/v1/dev/simulate")
    def dev_simulate():
        need_dev()
        need_key()
        from .client import InProcessTransport, run_session
        from .generator import SCENARIOS, build_session

        body = request.get_json(silent=True) or {}
        scenario = body.get("scenario")
        if scenario not in SCENARIOS:
            raise ValidationFailure(400, "invalid_request", f"scenario must be one of {list(SCENARIOS)}")
        seed = body.get("seed", int(time.time() * 1000) % 1_000_000)
        if not isinstance(seed, int) or isinstance(seed, bool):
            raise ValidationFailure(400, "invalid_request", "seed must be an integer")
        session = build_session(scenario, int(clock() * 1000), seed)
        status, result = run_session(InProcessTransport(current_app._get_current_object(), api_key=api_key), session,
                                     now_ms=int(clock() * 1000))
        return jsonify({"scenario": scenario, "seed": seed, "status": status, "result": result}), 200
