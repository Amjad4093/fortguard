"""Back office: analyst logins, case management, audit log, rule settings, users and reports.

Storage is SQLite (standard library). Portal users sign in with a username and password and get a
bearer token; the bank backend keeps using its X-API-Key on the decision endpoints.

Roles
    viewer   read everything except users and the audit log
    analyst  viewer + work cases (status, assignee, notes) + revoke devices
    admin    analyst + edit rules and bands + manage users + read the audit log

Every change an analyst or admin makes is written to the audit log with who, what, when and the
before/after values.

Endpoints (all under /v1/bo, bearer token unless noted)
    POST /v1/auth/login            {username, password} -> {token, user}       (no token)
    POST /v1/auth/logout
    GET  /v1/auth/me
    GET  /v1/bo/overview           counts and recent trend for the dashboard
    GET  /v1/bo/cases              ?status=&q=&limit=
    GET  /v1/bo/cases/<id>
    POST /v1/bo/cases/<id>         {status?, assignee?}                         analyst
    POST /v1/bo/cases/<id>/notes   {text}                                       analyst
    GET  /v1/bo/decisions          ?level=&limit=
    GET  /v1/bo/devices
    POST /v1/bo/devices/<id>/revoke                                             analyst
    GET  /v1/bo/rules
    PUT  /v1/bo/rules              {weights?, bands?}                           admin
    GET  /v1/bo/users                                                           admin
    POST /v1/bo/users              {username, password, role}                   admin
    POST /v1/bo/users/<username>   {role?, active?, password?}                  admin
    GET  /v1/bo/audit              ?limit=                                      admin
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import Counter, defaultdict

from flask import g, jsonify, request

from . import config
from .schema import ValidationFailure

ROLES = ("viewer", "analyst", "admin")
RANK = {r: i for i, r in enumerate(ROLES)}
CASE_STATUSES = ("OPEN", "INVESTIGATING", "CONFIRMED_FRAUD", "FALSE_POSITIVE", "CLOSED")
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,32}$")
TOKEN_TTL_S = 8 * 3600
MAX_FAILED_LOGINS = 5
LOCKOUT_S = 300
MIN_PASSWORD = 10

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, pw_hash TEXT NOT NULL, role TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1, created_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, time_ms INTEGER NOT NULL, session_id TEXT NOT NULL,
    risk_level TEXT NOT NULL, risk_score INTEGER NOT NULL, record TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS decisions_time ON decisions(time_ms);
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT UNIQUE NOT NULL,
    created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, status TEXT NOT NULL,
    assignee TEXT, risk_level TEXT NOT NULL, risk_score INTEGER NOT NULL,
    user_id TEXT, device_guid TEXT, decision TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS cases_status ON cases(status);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL, author TEXT NOT NULL,
    text TEXT NOT NULL, created_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, time_ms INTEGER NOT NULL, actor TEXT NOT NULL,
    action TEXT NOT NULL, target TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


# --- Passwords -------------------------------------------------------------------------------------

def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + salt.hex() + "$" + digest.hex()


def check_password(password, stored):
    try:
        _, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


# --- Store -------------------------------------------------------------------------------------------

class BackOffice:
    """All back-office state. One SQLite connection guarded by a lock (fine for one process)."""

    def __init__(self, path, clock=time.time):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.clock = clock
        self._failed = defaultdict(list)
        with self.lock:
            self.db.executescript(SCHEMA)
            self.db.commit()
        self.defaults = {"weights": dict(config.WEIGHTS), "bands": json.loads(json.dumps(config.BANDS))}

    def now_ms(self):
        return int(self.clock() * 1000)

    def q(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def x(self, sql, args=()):
        with self.lock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur

    # users and tokens
    def ensure_admin(self, password):
        if self.q("SELECT 1 FROM users LIMIT 1"):
            return False
        self.x("INSERT INTO users VALUES (?,?,?,?,?)", ("admin", hash_password(password), "admin", 1, self.now_ms()))
        self.audit("system", "user_create", "admin", {"role": "admin", "reason": "first start"})
        return True

    def login(self, username, password):
        now = self.clock()
        recent = [t for t in self._failed[username] if now - t < LOCKOUT_S]
        self._failed[username] = recent
        if len(recent) >= MAX_FAILED_LOGINS:
            raise ValidationFailure(429, "locked", "too many failed attempts; try again in a few minutes")
        rows = self.q("SELECT * FROM users WHERE username=?", (username,))
        user = rows[0] if rows else None
        ok = user is not None and user["active"] and check_password(password, user["pw_hash"])
        if not user:
            check_password(password, hash_password("timing-equaliser"))  # same work either way
        if not ok:
            self._failed[username].append(now)
            self.audit(username or "?", "login_failed", username, None)
            raise ValidationFailure(401, "bad_credentials", "wrong username or password")
        self._failed.pop(username, None)
        token = secrets.token_urlsafe(32)
        self.x("DELETE FROM tokens WHERE expires_ms < ?", (self.now_ms(),))
        self.x("INSERT INTO tokens VALUES (?,?,?)", (_token_hash(token), username, self.now_ms() + TOKEN_TTL_S * 1000))
        self.audit(username, "login", username, None)
        return token, {"username": username, "role": user["role"]}

    def user_for_token(self, token):
        rows = self.q(
            "SELECT u.username, u.role, u.active, t.expires_ms FROM tokens t JOIN users u ON u.username=t.username "
            "WHERE t.token_hash=?", (_token_hash(token),))
        if not rows or not rows[0]["active"] or rows[0]["expires_ms"] < self.now_ms():
            return None
        return {"username": rows[0]["username"], "role": rows[0]["role"]}

    def logout(self, token):
        self.x("DELETE FROM tokens WHERE token_hash=?", (_token_hash(token),))

    # audit
    def audit(self, actor, action, target, detail):
        self.x("INSERT INTO audit (time_ms, actor, action, target, detail) VALUES (?,?,?,?,?)",
               (self.now_ms(), actor, action, target, json.dumps(detail) if detail is not None else None))

    # decisions and cases
    def record_decision(self, entry):
        self.x("INSERT INTO decisions (time_ms, session_id, risk_level, risk_score, record) VALUES (?,?,?,?,?)",
               (entry["time_ms"], entry["session_id"], entry["risk_level"], entry["risk_score"], json.dumps(entry)))
        if entry["risk_level"] in ("STEP_UP", "BLOCK"):
            existing = self.q("SELECT id, risk_score FROM cases WHERE session_id=?", (entry["session_id"],))
            if existing:
                if entry["risk_score"] >= existing[0]["risk_score"]:
                    self.x("UPDATE cases SET updated_ms=?, risk_level=?, risk_score=?, decision=? WHERE id=?",
                           (entry["time_ms"], entry["risk_level"], entry["risk_score"], json.dumps(entry), existing[0]["id"]))
            else:
                self.x("INSERT INTO cases (session_id, created_ms, updated_ms, status, assignee, risk_level, risk_score, "
                       "user_id, device_guid, decision) VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (entry["session_id"], entry["time_ms"], entry["time_ms"], "OPEN", None, entry["risk_level"],
                        entry["risk_score"], entry.get("user_id"), entry.get("device_guid"), json.dumps(entry)))

    # rules
    def load_rules(self):
        """Apply rule settings saved earlier, if any."""
        rows = self.q("SELECT value FROM settings WHERE key='rules'")
        if rows:
            saved = json.loads(rows[0]["value"])
            config.WEIGHTS.update({k: v for k, v in saved.get("weights", {}).items() if k in config.WEIGHTS})
            if "bands" in saved:
                config.BANDS["default"].update(saved["bands"])

    def save_rules(self):
        self.x("INSERT OR REPLACE INTO settings VALUES ('rules', ?)",
               (json.dumps({"weights": config.WEIGHTS, "bands": config.BANDS["default"]}),))


def _case_row(r, with_decision=False):
    d = json.loads(r["decision"])
    out = {
        "id": r["id"], "session_id": r["session_id"], "status": r["status"], "assignee": r["assignee"],
        "created_ms": r["created_ms"], "updated_ms": r["updated_ms"], "risk_level": r["risk_level"],
        "risk_score": r["risk_score"], "user_id": r["user_id"], "device_guid": r["device_guid"],
        "amount": d.get("amount"), "currency": d.get("currency"),
        "top_reason": d["score_breakdown"][0]["reason"] if d.get("score_breakdown") else None,
    }
    if with_decision:
        out["decision"] = d
    return out


# --- HTTP -----------------------------------------------------------------------------------------------

def register(app, *, bo, api_key, registry, dev_mode):
    def body():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ValidationFailure(400, "invalid_json", "body must be a JSON object")
        return data

    def need(role):
        header = request.headers.get("Authorization", "")
        token = header[7:] if header.startswith("Bearer ") else None
        user = bo.user_for_token(token) if token else None
        if user is None:
            raise ValidationFailure(401, "not_signed_in", "sign in first")
        if RANK[user["role"]] < RANK[role]:
            raise ValidationFailure(403, "forbidden", f"needs the {role} role")
        g.user, g.token = user, token
        return user

    # auth
    @app.post("/v1/auth/login")
    def bo_login():
        data = body()
        username = str(data.get("username", "")).strip().lower()
        token, user = bo.login(username, str(data.get("password", "")))
        return jsonify({"token": token, "user": user, "expires_in_s": TOKEN_TTL_S})

    @app.post("/v1/auth/logout")
    def bo_logout():
        user = need("viewer")
        bo.logout(g.token)
        bo.audit(user["username"], "logout", user["username"], None)
        return jsonify({"ok": True})

    @app.get("/v1/auth/me")
    def bo_me():
        return jsonify({"user": need("viewer"), "dev_mode": dev_mode})

    # dashboard
    @app.get("/v1/bo/overview")
    def bo_overview():
        need("viewer")
        since = bo.now_ms() - 24 * 3600 * 1000
        rows = bo.q("SELECT time_ms, risk_level, record FROM decisions WHERE time_ms >= ? ORDER BY time_ms", (since,))
        levels = Counter(r["risk_level"] for r in rows)
        reasons = Counter()
        hourly = defaultdict(lambda: {"ALLOW": 0, "STEP_UP": 0, "BLOCK": 0})
        for r in rows:
            for code in json.loads(r["record"]).get("reason_codes", []):
                reasons[code] += 1
            hourly[(r["time_ms"] // 3_600_000) * 3_600_000][r["risk_level"]] += 1
        statuses = Counter(r["status"] for r in bo.q("SELECT status FROM cases"))
        return jsonify({
            "last_24h": {"total": len(rows), "ALLOW": levels["ALLOW"], "STEP_UP": levels["STEP_UP"], "BLOCK": levels["BLOCK"]},
            "top_reasons": reasons.most_common(8),
            "hourly": [{"hour_ms": h, **hourly[h]} for h in
                       range((since // 3_600_000 + 1) * 3_600_000, bo.now_ms() + 1, 3_600_000)] if rows else [],
            "cases": {s: statuses[s] for s in CASE_STATUSES},
            "devices": {"total": len(registry.all()), "revoked": sum(1 for d in registry.all() if d.status != "ACTIVE")},
        })

    # cases
    @app.get("/v1/bo/cases")
    def bo_cases():
        need("viewer")
        status, text = request.args.get("status"), request.args.get("q", "").strip()
        sql, args = "SELECT * FROM cases WHERE 1=1", []
        if status:
            if status not in CASE_STATUSES:
                raise ValidationFailure(400, "invalid_request", "unknown status")
            sql += " AND status=?"; args.append(status)
        if text:
            sql += " AND (session_id LIKE ? OR user_id LIKE ? OR device_guid LIKE ?)"; args += [f"%{text}%"] * 3
        limit = _limit(request.args.get("limit"), 200)
        rows = bo.q(sql + " ORDER BY CASE status WHEN 'OPEN' THEN 0 WHEN 'INVESTIGATING' THEN 1 ELSE 2 END, risk_score DESC, updated_ms DESC LIMIT ?", args + [limit])
        counts = Counter(r["status"] for r in bo.q("SELECT status FROM cases"))
        return jsonify({"cases": [_case_row(r) for r in rows], "counts": {s: counts[s] for s in CASE_STATUSES}})

    def get_case(case_id):
        rows = bo.q("SELECT * FROM cases WHERE id=?", (case_id,))
        if not rows:
            raise ValidationFailure(404, "unknown_case", "no such case")
        return rows[0]

    @app.get("/v1/bo/cases/<int:case_id>")
    def bo_case(case_id):
        need("viewer")
        row = get_case(case_id)
        out = _case_row(row, with_decision=True)
        out["notes"] = [dict(n) for n in bo.q("SELECT author, text, created_ms FROM notes WHERE case_id=? ORDER BY id", (case_id,))]
        out["history"] = [
            {"time_ms": a["time_ms"], "actor": a["actor"], "action": a["action"], "detail": json.loads(a["detail"]) if a["detail"] else None}
            for a in bo.q("SELECT * FROM audit WHERE target=? ORDER BY id", (f"case:{case_id}",))
        ]
        device = registry.get(row["device_guid"]) if row["device_guid"] else None
        out["device"] = {"status": device.status, "integrity_level": device.integrity, "platform": device.platform} if device else None
        out["other_sessions"] = [
            dict(r) for r in bo.q("SELECT id, session_id, risk_level, risk_score, status FROM cases WHERE user_id=? AND id<>? ORDER BY id DESC LIMIT 10",
                                  (row["user_id"], case_id))
        ]
        return jsonify(out)

    @app.post("/v1/bo/cases/<int:case_id>")
    def bo_case_update(case_id):
        user = need("analyst")
        row = get_case(case_id)
        data = body()
        changes = {}
        if "status" in data:
            if data["status"] not in CASE_STATUSES:
                raise ValidationFailure(400, "invalid_request", f"status must be one of {list(CASE_STATUSES)}")
            changes["status"] = data["status"]
        if "assignee" in data:
            assignee = data["assignee"]
            if assignee is not None and not bo.q("SELECT 1 FROM users WHERE username=? AND active=1", (assignee,)):
                raise ValidationFailure(400, "invalid_request", "assignee must be an active user")
            changes["assignee"] = assignee
        if not changes:
            raise ValidationFailure(400, "invalid_request", "nothing to change")
        before = {k: row[k] for k in changes}
        sets = ", ".join(f"{k}=?" for k in changes)
        bo.x(f"UPDATE cases SET {sets}, updated_ms=? WHERE id=?", list(changes.values()) + [bo.now_ms(), case_id])
        bo.audit(user["username"], "case_update", f"case:{case_id}", {"before": before, "after": changes})
        return jsonify(_case_row(get_case(case_id)))

    @app.post("/v1/bo/cases/<int:case_id>/notes")
    def bo_case_note(case_id):
        user = need("analyst")
        get_case(case_id)
        text = str(body().get("text", "")).strip()
        if not 1 <= len(text) <= 2000:
            raise ValidationFailure(400, "invalid_request", "a note needs 1 to 2000 characters")
        bo.x("INSERT INTO notes (case_id, author, text, created_ms) VALUES (?,?,?,?)", (case_id, user["username"], text, bo.now_ms()))
        bo.x("UPDATE cases SET updated_ms=? WHERE id=?", (bo.now_ms(), case_id))
        bo.audit(user["username"], "note_add", f"case:{case_id}", {"length": len(text)})
        return jsonify({"ok": True}), 201

    # decisions and devices
    @app.get("/v1/bo/decisions")
    def bo_decisions():
        need("viewer")
        level = request.args.get("level")
        limit = _limit(request.args.get("limit"), 200)
        if level:
            rows = bo.q("SELECT record FROM decisions WHERE risk_level=? ORDER BY id DESC LIMIT ?", (level, limit))
        else:
            rows = bo.q("SELECT record FROM decisions ORDER BY id DESC LIMIT ?", (limit,))
        return jsonify({"decisions": [json.loads(r["record"]) for r in rows]})

    @app.get("/v1/bo/devices")
    def bo_devices():
        need("viewer")
        rows = [
            {"device_guid": d.device_guid, "app_id": d.app_id, "platform": d.platform, "integrity_level": d.integrity,
             "status": d.status, "key_version": d.key_version, "key_sha256": d.key_sha256[:16],
             "enrolled_at_ms": int(d.enrolled_at * 1000)}
            for d in registry.all()
        ]
        rows.sort(key=lambda r: -r["enrolled_at_ms"])
        return jsonify({"devices": rows})

    @app.post("/v1/bo/devices/<device_guid>/revoke")
    def bo_device_revoke(device_guid):
        user = need("analyst")
        if not registry.revoke(device_guid):
            raise ValidationFailure(404, "unknown_device", "no such device")
        bo.audit(user["username"], "device_revoke", f"device:{device_guid}", None)
        return jsonify({"device_guid": device_guid, "status": "REVOKED"})

    # rules
    def rules_view():
        return {"weights": dict(config.WEIGHTS), "bands": dict(config.BANDS["default"]),
                "defaults": bo.defaults, "score_max": config.SCORE_MAX}

    @app.get("/v1/bo/rules")
    def bo_rules():
        need("viewer")
        return jsonify(rules_view())

    @app.put("/v1/bo/rules")
    def bo_rules_update():
        user = need("admin")
        data = body()
        weights = data.get("weights", {})
        bands = data.get("bands", {})
        if not isinstance(weights, dict) or not isinstance(bands, dict):
            raise ValidationFailure(400, "invalid_request", "weights and bands must be objects")
        for code, value in weights.items():
            if code not in config.WEIGHTS:
                raise ValidationFailure(400, "invalid_request", f"unknown rule {code}")
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= config.SCORE_MAX:
                raise ValidationFailure(400, "invalid_request", f"{code} must be a whole number from 0 to {config.SCORE_MAX}")
        new_bands = dict(config.BANDS["default"])
        for name in bands:
            if name not in new_bands:
                raise ValidationFailure(400, "invalid_request", f"unknown band {name}")
            if not isinstance(bands[name], int) or isinstance(bands[name], bool):
                raise ValidationFailure(400, "invalid_request", f"{name} must be a whole number")
        new_bands.update(bands)
        if not 1 <= new_bands["step_up_from"] < new_bands["block_from"] <= config.SCORE_MAX:
            raise ValidationFailure(400, "invalid_request", "bands must satisfy 1 <= step_up_from < block_from <= 1000")
        before = {"weights": {k: config.WEIGHTS[k] for k in weights}, "bands": dict(config.BANDS["default"])}
        config.WEIGHTS.update(weights)
        config.BANDS["default"].update(new_bands)
        bo.save_rules()
        bo.audit(user["username"], "rules_update", "rules", {"before": before, "after": {"weights": weights, "bands": new_bands}})
        return jsonify(rules_view())

    # users
    @app.get("/v1/bo/users")
    def bo_users():
        need("admin")
        return jsonify({"users": [
            {"username": r["username"], "role": r["role"], "active": bool(r["active"]), "created_ms": r["created_ms"]}
            for r in bo.q("SELECT * FROM users ORDER BY username")
        ], "roles": list(ROLES)})

    def check_new_password(pw):
        if not isinstance(pw, str) or len(pw) < MIN_PASSWORD:
            raise ValidationFailure(400, "weak_password", f"password needs at least {MIN_PASSWORD} characters")

    @app.post("/v1/bo/users")
    def bo_user_create():
        user = need("admin")
        data = body()
        username = str(data.get("username", "")).strip().lower()
        if not USERNAME_RE.match(username):
            raise ValidationFailure(400, "invalid_request", "username: 3 to 32 of a-z, 0-9, dot, dash, underscore")
        if data.get("role") not in ROLES:
            raise ValidationFailure(400, "invalid_request", f"role must be one of {list(ROLES)}")
        check_new_password(data.get("password"))
        if bo.q("SELECT 1 FROM users WHERE username=?", (username,)):
            raise ValidationFailure(409, "exists", "that username is taken")
        bo.x("INSERT INTO users VALUES (?,?,?,?,?)", (username, hash_password(data["password"]), data["role"], 1, bo.now_ms()))
        bo.audit(user["username"], "user_create", f"user:{username}", {"role": data["role"]})
        return jsonify({"username": username, "role": data["role"], "active": True}), 201

    @app.post("/v1/bo/users/<username>")
    def bo_user_update(username):
        user = need("admin")
        rows = bo.q("SELECT * FROM users WHERE username=?", (username,))
        if not rows:
            raise ValidationFailure(404, "unknown_user", "no such user")
        data = body()
        changes, detail = {}, {}
        if "role" in data:
            if data["role"] not in ROLES:
                raise ValidationFailure(400, "invalid_request", f"role must be one of {list(ROLES)}")
            changes["role"] = data["role"]; detail["role"] = {"before": rows[0]["role"], "after": data["role"]}
        if "active" in data:
            if not isinstance(data["active"], bool):
                raise ValidationFailure(400, "invalid_request", "active must be true or false")
            changes["active"] = int(data["active"]); detail["active"] = data["active"]
        if "password" in data:
            check_new_password(data["password"])
            changes["pw_hash"] = hash_password(data["password"]); detail["password"] = "changed"
        if not changes:
            raise ValidationFailure(400, "invalid_request", "nothing to change")
        if username == user["username"] and (changes.get("active") == 0 or changes.get("role", "admin") != "admin"):
            raise ValidationFailure(400, "invalid_request", "you cannot demote or deactivate yourself")
        sets = ", ".join(f"{k}=?" for k in changes)
        bo.x(f"UPDATE users SET {sets} WHERE username=?", list(changes.values()) + [username])
        if changes.get("active") == 0 or "pw_hash" in changes:
            bo.x("DELETE FROM tokens WHERE username=?", (username,))
        bo.audit(user["username"], "user_update", f"user:{username}", detail)
        return jsonify({"ok": True})

    @app.get("/v1/bo/audit")
    def bo_audit():
        need("admin")
        limit = _limit(request.args.get("limit"), 300)
        return jsonify({"audit": [
            {"time_ms": r["time_ms"], "actor": r["actor"], "action": r["action"], "target": r["target"],
             "detail": json.loads(r["detail"]) if r["detail"] else None}
            for r in bo.q("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
        ]})


def register_dev(app, *, bo, api_key, clock, dev_mode):
    """Dev mode only: let a signed-in analyst fill the portal with synthetic sessions."""
    from flask import current_app

    @app.post("/v1/bo/dev/simulate")
    def bo_dev_simulate():
        if not dev_mode:
            raise ValidationFailure(404, "not_found", "no such endpoint")
        header = request.headers.get("Authorization", "")
        user = bo.user_for_token(header[7:]) if header.startswith("Bearer ") else None
        if user is None:
            raise ValidationFailure(401, "not_signed_in", "sign in first")
        if RANK[user["role"]] < RANK["analyst"]:
            raise ValidationFailure(403, "forbidden", "needs the analyst role")
        from .client import InProcessTransport, run_session
        from .generator import SCENARIOS, build_session

        transport = InProcessTransport(current_app._get_current_object(), api_key=api_key)
        seed0 = int(clock() * 1000) % 1_000_000
        results = []
        for i, name in enumerate(SCENARIOS):
            status, body = run_session(transport, build_session(name, int(clock() * 1000), seed0 + i), now_ms=int(clock() * 1000))
            results.append({"scenario": name, "risk_level": body.get("risk_level"), "risk_score": body.get("risk_score")})
        bo.audit(user["username"], "dev_simulate", "scenarios", {"count": len(results)})
        return jsonify({"results": results})


def _limit(value, default):
    if value is None:
        return default
    try:
        return max(1, min(int(value), 1000))
    except ValueError:
        raise ValidationFailure(400, "invalid_request", "limit must be a number")
