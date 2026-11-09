"""Request IDs, security headers, rate limits, access logs and Prometheus metrics.

Rate limits (per minute, token bucket; see config.RATE_LIMITS):
    login        per client IP          brute-force protection on top of the per-user lockout
    challenge    per client IP          the only unauthenticated device endpoint
    telemetry    per device             one phone cannot flood the ingest path
    evaluate     per API key            protects scoring capacity
A limited request gets 429 rate_limited with a Retry-After header.

Client IP: the socket address, or the first X-Forwarded-For entry when FORTGUARD_TRUST_PROXY=1
(set this only behind a proxy you control, such as Render's, or anyone can choose their own IP).

/metrics (Prometheus text format) needs the bank API key, as X-API-Key or "Authorization: Bearer <key>".
"""

import json
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict

from flask import Response, g, request

from . import config

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{8,64}$")
LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)
access_log = logging.getLogger("fortguard.access")


class RateLimiter:
    """Token buckets keyed by (rule, key). Memory is bounded: idle buckets are dropped."""

    def __init__(self, clock=time.time, max_keys=200_000):
        self.clock = clock
        self.max_keys = max_keys
        self._buckets = {}
        self._lock = threading.Lock()

    def allow(self, rule, key):
        if os.environ.get("FORTGUARD_RATE_LIMITS_OFF") == "1":  # load tests only
            return True, 0
        per_minute = config.RATE_LIMITS.get(rule)
        if not per_minute:
            return True, 0
        rate = per_minute / 60.0
        now = self.clock()
        with self._lock:
            if len(self._buckets) > self.max_keys:
                cutoff = now - 120
                self._buckets = {k: v for k, v in self._buckets.items() if v[1] > cutoff}
            tokens, last = self._buckets.get((rule, key), (float(per_minute), now))
            tokens = min(float(per_minute), tokens + (now - last) * rate)
            if tokens >= 1.0:
                self._buckets[(rule, key)] = (tokens - 1.0, now)
                return True, 0
            self._buckets[(rule, key)] = (tokens, now)
            return False, max(1, int((1.0 - tokens) / rate) + 1)


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self.requests = defaultdict(int)            # (route, method, status) -> count
        self.latency = defaultdict(lambda: [0] * (len(LATENCY_BUCKETS) + 1))  # route -> bucket counts
        self.latency_sum = defaultdict(float)
        self.latency_count = defaultdict(int)
        self.decisions = defaultdict(int)           # (level, degraded) -> count
        self.rate_limited = defaultdict(int)        # rule -> count

    def observe(self, route, method, status, seconds):
        with self._lock:
            self.requests[(route, method, status)] += 1
            buckets = self.latency[route]
            for i, bound in enumerate(LATENCY_BUCKETS):
                if seconds <= bound:
                    buckets[i] += 1
            buckets[-1] += 1
            self.latency_sum[route] += seconds
            self.latency_count[route] += 1

    def decision(self, level, degraded):
        with self._lock:
            self.decisions[(level, bool(degraded))] += 1

    def limited(self, rule):
        with self._lock:
            self.rate_limited[rule] += 1

    def render(self, gauges):
        lines = []
        with self._lock:
            lines += ["# HELP fortguard_requests_total HTTP requests by route, method and status.",
                      "# TYPE fortguard_requests_total counter"]
            for (route, method, status), n in sorted(self.requests.items()):
                lines.append(f'fortguard_requests_total{{route="{route}",method="{method}",status="{status}"}} {n}')
            lines += ["# HELP fortguard_request_seconds Request latency inside the server.",
                      "# TYPE fortguard_request_seconds histogram"]
            for route, buckets in sorted(self.latency.items()):
                for bound, n in zip(LATENCY_BUCKETS, buckets):
                    lines.append(f'fortguard_request_seconds_bucket{{route="{route}",le="{bound}"}} {n}')
                lines.append(f'fortguard_request_seconds_bucket{{route="{route}",le="+Inf"}} {buckets[-1]}')
                lines.append(f'fortguard_request_seconds_sum{{route="{route}"}} {self.latency_sum[route]:.6f}')
                lines.append(f'fortguard_request_seconds_count{{route="{route}"}} {self.latency_count[route]}')
            lines += ["# HELP fortguard_decisions_total Risk decisions by level.", "# TYPE fortguard_decisions_total counter"]
            for (level, degraded), n in sorted(self.decisions.items()):
                lines.append(f'fortguard_decisions_total{{level="{level}",degraded="{str(degraded).lower()}"}} {n}')
            lines += ["# HELP fortguard_rate_limited_total Requests refused by a rate limit.",
                      "# TYPE fortguard_rate_limited_total counter"]
            for rule, n in sorted(self.rate_limited.items()):
                lines.append(f'fortguard_rate_limited_total{{rule="{rule}"}} {n}')
        for name, (help_text, value) in sorted(gauges.items()):
            lines += [f"# HELP {name} {help_text}", f"# TYPE {name} gauge", f"{name} {value}"]
        return "\n".join(lines) + "\n"


def client_ip(trust_proxy):
    if trust_proxy:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return request.remote_addr or "unknown"


def register(app, *, api_key, store, registry, clock, error):
    trust_proxy = os.environ.get("FORTGUARD_TRUST_PROXY") == "1"
    limiter = RateLimiter(clock=clock)
    metrics = Metrics()
    app.fortguard_metrics = metrics
    app.fortguard_limiter = limiter

    def limit_key():
        """Which rate-limit rule applies to this request, and for whom."""
        path = request.path
        if request.method != "POST":
            return None
        if path == "/v1/auth/login":
            return "login", client_ip(trust_proxy)
        if path == "/v1/devices/challenge":
            return "challenge", client_ip(trust_proxy)
        if path == "/v1/telemetry/stream":
            body = request.get_json(silent=True) or {}
            device = body.get("device_guid") if isinstance(body, dict) else None
            return "telemetry", device if isinstance(device, str) else client_ip(trust_proxy)
        if path == "/v1/risk/evaluate":
            return "evaluate", request.headers.get("X-API-Key", "")[:16] or client_ip(trust_proxy)
        return None

    @app.before_request
    def _before():
        g.started = time.perf_counter()
        incoming = request.headers.get("X-Request-ID", "")
        g.request_id = incoming if REQUEST_ID_RE.match(incoming) else secrets.token_hex(8)
        rule_key = limit_key()
        if rule_key:
            ok, retry = limiter.allow(*rule_key)
            if not ok:
                metrics.limited(rule_key[0])
                resp, status = error(429, "rate_limited", "too many requests; slow down")
                resp.headers["Retry-After"] = str(retry)
                return resp, status

    @app.after_request
    def _after(resp):
        rid = getattr(g, "request_id", None) or secrets.token_hex(8)
        resp.headers["X-Request-ID"] = rid
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if resp.mimetype == "text/html":
            resp.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        elif request.path.startswith("/v1/"):
            resp.headers["Cache-Control"] = "no-store"
        route = request.url_rule.rule if request.url_rule else "unmatched"
        seconds = time.perf_counter() - getattr(g, "started", time.perf_counter())
        metrics.observe(route, request.method, resp.status_code, seconds)
        access_log.info(json.dumps({
            "request_id": rid, "method": request.method, "route": route, "status": resp.status_code,
            "ms": round(seconds * 1000, 2),
        }))
        return resp

    @app.get("/metrics")
    def _metrics():
        auth = request.headers.get("Authorization", "")
        given = request.headers.get("X-API-Key") or (auth[7:] if auth.startswith("Bearer ") else "")
        if not secrets.compare_digest(given.encode(), api_key.encode()):
            return error(401, "unauthorized", "metrics need the API key")
        devices = registry.all()
        gauges = {
            "fortguard_sessions_in_memory": ("Sessions currently held in memory.", store.count()),
            "fortguard_devices_enrolled": ("Enrolled devices.", len(devices)),
            "fortguard_devices_revoked": ("Revoked devices.", sum(1 for d in devices if d.status != "ACTIVE")),
        }
        return Response(metrics.render(gauges), mimetype="text/plain; version=0.0.4")
