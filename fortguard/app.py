"""HTTP API for the sprint 1 slice (Flask).

POST /v1/devices/challenge  one-time challenge for enrollment (device-facing)
POST /v1/devices/enroll     public key plus attestation in, device registered (device-facing)
POST /v1/devices/<id>/revoke  stop trusting a device (bank backend, X-API-Key)
POST /v1/telemetry/stream   SDK batch signed by the enrolled device key in, 202 with counts out
POST /v1/risk/evaluate      session and transaction in, score, level, action and reason codes out
GET  /healthz               liveness
GET  /portal, /v1/admin/*   analyst portal and its data (see admin.py); /phone and /v1/dev/* in dev mode only

Errors always look like {"error": {"code": "...", "message": "..."}}.
"""

import json
import os
import secrets
import time
from collections import OrderedDict

from flask import Flask, jsonify, request

from . import config
from .attestation import (
    DEV_AUTHORITY, AttestationError, AttestationNotConfigured, SimulatedVerifier,
)
from . import admin, backoffice, hardening
from .hardening import client_ip
from .baseline import Baselines
from .devices import ACTIVE, DeviceRegistry
from .schema import ID_RE, ValidationFailure, validate_enroll, validate_evaluate, validate_feedback, validate_telemetry
from .scoring import degraded_decision, score_session
from .signing import key_sha256, load_public_key, verify_owner_proof, verify_payload
from .store import DeviceMismatch, ReplayDetected, SessionStore

DEV_API_KEY = "dev-only-api-key"
DEV_ADMIN_PASSWORD = "fortguard-admin-dev"


def _error(status, code, message):
    return jsonify({"error": {"code": code, "message": message}}), status


class _NoSession:
    """Stands in for a session with no telemetry when answering in degraded mode."""

    device_guid = None
    integrity = None

    def __init__(self, user_id):
        self.user_id = user_id


def _start_purge_job(bo, baselines):
    """Hourly retention purge in a background thread (one server process)."""
    import logging
    import threading

    def loop():
        while True:
            time.sleep(config.PURGE_EVERY_S)
            try:
                out = bo.purge(baselines)
                bo.audit("system", "purge", "retention", out)
            except Exception:  # keep the job alive whatever happens
                logging.getLogger("fortguard").exception("retention purge failed")

    threading.Thread(target=loop, name="fortguard-purge", daemon=True).start()


def _batch_span_ms(payload):
    """Time from the first to the last reading in one batch: the time in the app that the batch covers."""
    times = [e["timestamp_ms"] for e in payload.get("touch_events", [])]
    times += [e["ts"] for e in payload.get("key_events", [])] + [e["ts"] for e in payload.get("ui_events", [])]
    for samples in (payload.get("sensor_data") or {}).values():
        times += [s["ts"] for s in samples]
    return max(times) - min(times) if times else 0


def create_app(api_key=None, clock=time.time, store=None, registry=None, verifier=None,
               allowed_app_ids=None, dev_mode=None, db_path=None, admin_password=None,
               start_jobs=False):
    """Build the app.

    The API key comes from the argument, then FORTGUARD_API_KEY, then a development value.
    The default verifier is the SIMULATED attestation authority: development and tests only.
    Dev mode (argument, or FORTGUARD_DEV_MODE=1) switches on the browser test client and the
    simulated-attestation endpoint. Never run it where real users or real money are involved.

    Back-office data goes to db_path, else FORTGUARD_DATA_DIR/fortguard.db, else memory (tests).
    The first portal user is "admin" with admin_password, else FORTGUARD_ADMIN_PASSWORD, else a
    fixed development password in dev mode, else a random one printed at start.
    """
    trust_proxy = os.environ.get("FORTGUARD_TRUST_PROXY") == "1"
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_BODY_BYTES
    api_key = api_key or os.environ.get("FORTGUARD_API_KEY") or DEV_API_KEY
    store = store or SessionStore(clock=clock)
    registry = registry or DeviceRegistry(clock=clock)
    verifier = verifier or SimulatedVerifier(DEV_AUTHORITY.public_key)
    allowed_app_ids = tuple(allowed_app_ids or config.ALLOWED_APP_IDS)
    app.fortguard_store = store
    app.fortguard_registry = registry
    if dev_mode is None:
        dev_mode = os.environ.get("FORTGUARD_DEV_MODE") == "1"
    decisions = admin.DecisionLog()
    app.fortguard_decisions = decisions
    if db_path is None:
        data_dir = os.environ.get("FORTGUARD_DATA_DIR")
        db_path = os.path.join(data_dir, "fortguard.db") if data_dir else ":memory:"
    bo = backoffice.BackOffice(db_path, clock=clock)
    bo.load_rules()
    password = admin_password or os.environ.get("FORTGUARD_ADMIN_PASSWORD") or (DEV_ADMIN_PASSWORD if dev_mode else None)
    generated = password is None
    if generated:
        password = secrets.token_urlsafe(12)
    if bo.ensure_admin(password):
        app.fortguard_first_admin_password = password if generated or password == DEV_ADMIN_PASSWORD else None
    app.fortguard_backoffice = bo
    baselines = Baselines(bo)
    app.fortguard_baselines = baselines
    if start_jobs:
        _start_purge_job(bo, baselines)
    idempotent = OrderedDict()

    def read_json():
        raw = request.get_data()
        try:
            return json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise ValidationFailure(400, "invalid_json", "body is not valid JSON")

    hardening.register(app, api_key=api_key, store=store, registry=registry, clock=clock, error=_error)

    @app.errorhandler(ValidationFailure)
    def _validation(exc):
        return _error(exc.status, exc.code, exc.message)

    @app.errorhandler(413)
    def _too_large(_):
        return _error(413, "body_too_large", f"body is larger than {config.MAX_BODY_BYTES} bytes")

    @app.errorhandler(404)
    def _not_found(_):
        return _error(404, "not_found", "no such endpoint")

    @app.errorhandler(405)
    def _bad_method(_):
        return _error(405, "method_not_allowed", "method not allowed")

    @app.errorhandler(Exception)
    def _unexpected(exc):
        app.logger.exception("unhandled error")
        return _error(500, "internal_error", "unexpected error")

    @app.get("/healthz")
    def healthz():
        return jsonify({"status": "ok", "model_version": config.MODEL_VERSION})

    @app.post("/v1/devices/challenge")
    def device_challenge():
        challenge = registry.issue_challenge()
        if challenge is None:
            return _error(503, "busy", "too many open challenges, retry shortly")
        return jsonify({"challenge": challenge, "expires_in_s": config.CHALLENGE_TTL_S}), 201

    @app.post("/v1/devices/enroll")
    def device_enroll():
        body = validate_enroll(read_json())
        if body["app_id"] not in allowed_app_ids:
            return _error(403, "app_not_allowed", "this app is not allowed to enroll devices")
        existing = registry.get(body["device_guid"])
        if existing is not None and existing.status != ACTIVE:
            return _error(403, "device_revoked", "this device was revoked")
        # Burn the challenge before any other check, so a failed attempt cannot be retried with it.
        if not registry.consume_challenge(body["challenge"]):
            return _error(400, "invalid_challenge", "challenge is unknown, expired or already used")
        try:
            key = load_public_key(body["public_key"])
        except ValueError:
            return _error(400, "invalid_public_key", "public_key must be a base64url P-256 SPKI key")
        try:
            level = verifier.verify(
                token=body["attestation"], device_guid=body["device_guid"], app_id=body["app_id"],
                platform=body["platform"], challenge=body["challenge"], key_sha256=key_sha256(key),
                now_ms=clock() * 1000,
            )
        except AttestationError as exc:
            return _error(exc.status, exc.code, exc.message)
        except AttestationNotConfigured as exc:
            return _error(501, "attestation_not_configured", str(exc))
        device = registry.enroll(body["device_guid"], body["app_id"], body["platform"], key, level)
        return jsonify({
            "device_guid": device.device_guid, "integrity_level": device.integrity,
            "key_version": device.key_version, "key_sha256": device.key_sha256,
        }), 201

    @app.post("/v1/devices/<device_guid>/revoke")
    def device_revoke(device_guid):
        if request.headers.get("X-API-Key") != api_key:
            return _error(401, "unauthorized", "missing or wrong X-API-Key")
        if not ID_RE.match(device_guid) or not registry.revoke(device_guid):
            return _error(404, "unknown_device", "no such device")
        return jsonify({"device_guid": device_guid, "status": "REVOKED"})

    @app.post("/v1/telemetry/stream")
    def telemetry():
        payload = validate_telemetry(read_json())
        device = registry.get(payload["device_guid"])
        if device is None:
            return _error(401, "unknown_device", "device is not enrolled")
        if device.status != ACTIVE:
            return _error(401, "device_revoked", "this device was revoked")
        if payload["app_id"] != device.app_id:
            return _error(403, "app_mismatch", "app_id does not match the enrolled app")
        if not verify_payload(payload, device.key):
            return _error(401, "bad_signature", "signature is missing or does not match the payload")
        owner_proved = False
        if "owner_proof" in payload:
            owner_key = verify_owner_proof(payload)
            if owner_key is None:
                return _error(401, "bad_owner_proof", "owner proof does not verify")
            fingerprint = key_sha256(owner_key)
            if device.owner_key_sha256 is None:
                registry.set_owner_key(device.device_guid, fingerprint)  # first owner key on this device
            elif device.owner_key_sha256 != fingerprint:
                return _error(403, "owner_key_mismatch", "a different owner key is enrolled on this device")
            owner_proved = True
        skew = abs(clock() * 1000 - payload["timestamp_ms"])
        if skew > config.MAX_SKEW_MS:
            return _error(400, "stale_timestamp", "timestamp_ms is too far from server time")
        try:
            kept = store.ingest(payload, integrity=device.integrity, owner_proved=owner_proved,
                                ip=client_ip(trust_proxy))
        except ReplayDetected:
            return _error(409, "replay_detected", "this nonce was already used for the session")
        except DeviceMismatch:
            return _error(409, "device_mismatch", "session belongs to a different device")
        if payload.get("user_id"):  # the customer using the app, when the app says who it is
            bo.note_activity(payload["user_id"], _batch_span_ms(payload), payload.get("customer_name"))
        return jsonify({"session_id": payload["session_id"], "accepted": kept}), 202

    @app.post("/v1/risk/evaluate")
    def evaluate():
        if request.headers.get("X-API-Key") != api_key:
            return _error(401, "unauthorized", "missing or wrong X-API-Key")
        body = validate_evaluate(read_json())
        request_id = body.get("request_id")
        if request_id and request_id in idempotent:
            cached_body, cached_status = idempotent[request_id]
            return jsonify(cached_body), cached_status

        session = store.get(body["session_id"])
        started = time.perf_counter()
        if session is None:
            if not body.get("allow_degraded"):
                return _error(404, "unknown_session", "no telemetry has been received for this session")
            # PRD fail policy: answer from the transaction alone, clearly marked as degraded.
            result = degraded_decision(body["event_type"], body.get("transaction_details"), "REASON_DEGRADED_NO_TELEMETRY")
            session = _NoSession(body["user_id"])
        else:
            with store.lock:
                if session.user_id not in (None, body["user_id"]):
                    return _error(409, "session_user_mismatch", "session was evaluated for another user")
                session.user_id = body["user_id"]
                try:
                    result = score_session(session, body["event_type"], body.get("transaction_details"),
                                           baselines=baselines, user_id=body["user_id"])
                except Exception:
                    if not body.get("allow_degraded"):
                        raise
                    app.logger.exception("scoring failed; answering in degraded mode")
                    result = degraded_decision(body["event_type"], body.get("transaction_details"),
                                               "REASON_DEGRADED_SCORING_ERROR")
        feats = result.pop("_features", None)
        result["session_id"] = body["session_id"]
        result["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
        bo.record_decision(decisions.record(body, session, result, clock(), feats))
        app.fortguard_metrics.decision(result["risk_level"], result.get("degraded"))
        if feats is not None and (result["risk_level"] == "ALLOW" or getattr(session, "owner_proved", False)):
            baselines.learn(body["user_id"], body["session_id"], feats, int(clock() * 1000))

        if request_id:
            idempotent[request_id] = (result, 200)
            while len(idempotent) > config.MAX_IDEMPOTENCY_ENTRIES:
                idempotent.popitem(last=False)
        return jsonify(result), 200

    @app.post("/v1/feedback")
    def feedback():
        if request.headers.get("X-API-Key") != api_key:
            return _error(401, "unauthorized", "missing or wrong X-API-Key")
        body = validate_feedback(read_json())
        out = bo.apply_feedback(body["session_id"], body["label"], body.get("source"), body.get("note"), baselines)
        return jsonify(out), 201

    admin.register(app, api_key=api_key, store=store, registry=registry, decisions=decisions,
                   clock=clock, dev_mode=dev_mode)
    backoffice.register(app, bo=bo, api_key=api_key, registry=registry, dev_mode=dev_mode)
    backoffice.register_dev(app, bo=bo, api_key=api_key, clock=clock, dev_mode=dev_mode)
    return app


def main():  # pragma: no cover - manual run
    import argparse

    parser = argparse.ArgumentParser(description="FortGuard sprint 1 API")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    parser.add_argument("--dev", action="store_true", help="enable the /phone test client and simulated attestation")
    parser.add_argument("--https", action="store_true",
                        help="serve over HTTPS with a throwaway certificate (phones need HTTPS for crypto and sensors)")
    parser.add_argument("--data", default=os.environ.get("FORTGUARD_DATA_DIR", "data"),
                        help="folder for the back-office database (default: ./data)")
    args = parser.parse_args()
    app = create_app(dev_mode=True if args.dev else None, db_path=os.path.join(args.data, "fortguard.db"), start_jobs=True)
    dev = args.dev or os.environ.get("FORTGUARD_DEV_MODE") == "1"
    scheme = "https" if args.https else "http"
    shown = "<this computer's LAN address>" if args.host == "0.0.0.0" else args.host
    print(f"portal : {scheme}://{shown}:{args.port}/portal   (bank API key: {os.environ.get('FORTGUARD_API_KEY') or DEV_API_KEY})")
    first = getattr(app, "fortguard_first_admin_password", None)
    if first:
        print(f"first portal login: admin / {first}   (change it under Users)")
    if dev:
        print(f"phone  : {scheme}://{shown}:{args.port}/phone")
        print("DEV MODE: simulated attestation is on. Do not expose this to real users or real money.")
    app.run(host=args.host, port=args.port, ssl_context="adhoc" if args.https else None)


if __name__ == "__main__":  # pragma: no cover
    main()


def production_app():
    """Entry point for gunicorn: python -m gunicorn 'fortguard.app:production_app()'."""
    return create_app(start_jobs=True)
