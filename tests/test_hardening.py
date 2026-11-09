"""Request IDs, security headers, rate limits and the metrics endpoint."""

import pytest

from fortguard import config
from fortguard.app import create_app
from fortguard.client import InProcessTransport, run_session
from fortguard.hardening import RateLimiter


def test_every_response_has_a_request_id_and_security_headers(app):
    r = app.test_client().get("/healthz")
    assert len(r.headers["X-Request-ID"]) >= 8
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"


def test_a_valid_incoming_request_id_is_echoed_and_a_bad_one_replaced(app):
    c = app.test_client()
    assert c.get("/healthz", headers={"X-Request-ID": "req-from-bank-123"}).headers["X-Request-ID"] == "req-from-bank-123"
    assert c.get("/healthz", headers={"X-Request-ID": "<script>"}).headers["X-Request-ID"] != "<script>"


def test_pages_get_a_content_security_policy_and_api_is_not_cached(app):
    c = app.test_client()
    csp = c.get("/portal").headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp and "default-src 'self'" in csp
    assert c.post("/v1/devices/challenge", json={}).headers["Cache-Control"] == "no-store"


def test_hsts_only_over_https(app):
    c = app.test_client()
    assert "Strict-Transport-Security" not in c.get("/healthz").headers
    assert "max-age" in c.get("/healthz", headers={"X-Forwarded-Proto": "https"}).headers["Strict-Transport-Security"]


def test_errors_also_carry_the_headers(app):
    r = app.test_client().get("/nope")
    assert r.status_code == 404 and r.headers["X-Content-Type-Options"] == "nosniff" and "X-Request-ID" in r.headers


# --- Rate limits -------------------------------------------------------------------------------------------

def test_challenge_endpoint_is_rate_limited_per_ip(app, monkeypatch):
    monkeypatch.setitem(config.RATE_LIMITS, "challenge", 3)
    c = app.test_client()
    codes = [c.post("/v1/devices/challenge", json={}).status_code for _ in range(5)]
    assert codes == [201, 201, 201, 429, 429]
    r = c.post("/v1/devices/challenge", json={})
    assert r.get_json()["error"]["code"] == "rate_limited" and int(r.headers["Retry-After"]) >= 1


def test_limits_refill_over_time(clock, monkeypatch):
    monkeypatch.setitem(config.RATE_LIMITS, "challenge", 2)
    app = create_app(clock=clock)
    c = app.test_client()
    assert [c.post("/v1/devices/challenge", json={}).status_code for _ in range(3)] == [201, 201, 429]
    clock.now += 31  # 2 per minute: one token every 30 s
    assert c.post("/v1/devices/challenge", json={}).status_code == 201


def test_login_is_rate_limited_per_ip(app, monkeypatch):
    monkeypatch.setitem(config.RATE_LIMITS, "login", 2)
    c = app.test_client()
    codes = [c.post("/v1/auth/login", json={"username": f"u{i}", "password": "x"}).status_code for i in range(3)]
    assert codes == [401, 401, 429]


def test_telemetry_limit_is_per_device(api, enrolled, monkeypatch):
    monkeypatch.setitem(config.RATE_LIMITS, "telemetry", 1)
    a, b = enrolled("genuine", 1), enrolled("genuine", 2)
    assert api.post("/v1/telemetry/stream", a["batches"][0])[0] == 202
    assert api.post("/v1/telemetry/stream", a["batches"][1])[0] == 429
    assert api.post("/v1/telemetry/stream", b["batches"][0])[0] == 202  # another phone is unaffected


def test_forwarded_for_is_ignored_unless_trusted(app, monkeypatch):
    monkeypatch.setitem(config.RATE_LIMITS, "challenge", 1)
    c = app.test_client()
    assert c.post("/v1/devices/challenge", json={}, headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 201
    # a spoofed header does not buy a fresh bucket
    assert c.post("/v1/devices/challenge", json={}, headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 429


def test_forwarded_for_is_used_when_trusted(clock, monkeypatch):
    monkeypatch.setenv("FORTGUARD_TRUST_PROXY", "1")
    monkeypatch.setitem(config.RATE_LIMITS, "challenge", 1)
    c = create_app(clock=clock).test_client()
    assert c.post("/v1/devices/challenge", json={}, headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 201
    assert c.post("/v1/devices/challenge", json={}, headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 201
    assert c.post("/v1/devices/challenge", json={}, headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 429


def test_rate_limiter_memory_is_bounded():
    t = [0.0]
    rl = RateLimiter(clock=lambda: t[0], max_keys=100)
    for i in range(300):
        rl.allow("challenge", f"ip{i}")
    t[0] += 1000
    rl.allow("challenge", "fresh")
    assert len(rl._buckets) <= 101


# --- Metrics ----------------------------------------------------------------------------------------------------

def test_metrics_need_the_api_key(app):
    c = app.test_client()
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers={"X-API-Key": "wrong"}).status_code == 401


def test_metrics_report_requests_decisions_and_gauges(api, app, make_session):
    for scenario in ("genuine", "coached_scam", "bot_scripted"):
        run_session(api, make_session(scenario))
    text = app.test_client().get("/metrics", headers={"Authorization": f"Bearer {api.api_key}"}).get_data(as_text=True)
    assert 'fortguard_decisions_total{level="ALLOW",degraded="false"} 1' in text
    assert 'fortguard_decisions_total{level="BLOCK",degraded="false"} 1' in text
    assert 'fortguard_requests_total{route="/v1/risk/evaluate",method="POST",status="200"} 3' in text
    assert 'fortguard_request_seconds_bucket{route="/v1/risk/evaluate",le="+Inf"} 3' in text
    assert "fortguard_devices_enrolled 3" in text and "fortguard_sessions_in_memory 3" in text


def test_access_log_has_no_bodies(api, make_session, caplog):
    import logging
    caplog.set_level(logging.INFO, logger="fortguard.access")
    session = make_session("genuine")
    run_session(api, session)
    lines = [r.getMessage() for r in caplog.records if r.name == "fortguard.access"]
    assert lines and all('"request_id"' in l and '"route"' in l for l in lines)
    joined = " ".join(lines)
    assert session["evaluate"]["transaction_details"]["beneficiary_account"] not in joined
