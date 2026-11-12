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
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import Counter, defaultdict

from flask import g, jsonify, request

from . import config, customrules, mlmodel, rulelang
from .admin import SIGNAL_KEYS
from .schema import ValidationFailure

CPM_LABELS = ("under 100", "100–199", "200–299", "300–399", "400 and over")


def _cpm_bucket(cpm):
    """Typing speed bucket, characters per minute. Shown as a histogram on the dashboard."""
    for limit, label in ((100, CPM_LABELS[0]), (200, CPM_LABELS[1]), (300, CPM_LABELS[2]), (400, CPM_LABELS[3])):
        if cpm < limit:
            return label
    return CPM_LABELS[4]

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
CREATE TABLE IF NOT EXISTS customers (
    user_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, updated_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS usage (
    user_id TEXT PRIMARY KEY, first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL,
    active_ms INTEGER NOT NULL DEFAULT 0, batches INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, label TEXT NOT NULL,
    decided_level TEXT, source TEXT, note TEXT, time_ms INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS feedback_session ON feedback(session_id);
CREATE TABLE IF NOT EXISTS deny_list (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, value_hash TEXT NOT NULL, label TEXT NOT NULL,
    reason TEXT NOT NULL, added_by TEXT NOT NULL, created_ms INTEGER NOT NULL, expires_ms INTEGER,
    list TEXT NOT NULL DEFAULT 'deny', UNIQUE(kind, value_hash));
"""

# What the bank can put on its deny list. A match on any of them blocks the decision.
DENY_KINDS = ("customer", "device", "account", "ip")
DENY_MAX_DAYS = 3650
# The three lists. Only payee accounts can go on the mule and allow lists, and an account is on one list
# at a time.
#   deny   block outright
#   mule   suspected mule account: step up alone, block with almost any other signal
#   allow  trusted payee (the bank's own accounts, known billers): never treated as a new payee
LISTS = ("deny", "mule", "allow")
LIST_TEXT = {"deny": "deny list", "mule": "suspected-mule list", "allow": "trusted list"}


def _deny_value(kind, value):
    """The value in the one form it is compared in, or a ValidationFailure when it cannot be that kind."""
    if not isinstance(value, str):
        raise ValidationFailure(400, "invalid_request", "value must be text")
    value = value.strip()
    if kind == "customer" and re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", value):
        return value
    if kind == "device" and re.fullmatch(r"[A-Za-z0-9_\-]{8,64}", value):
        return value
    if kind == "account":
        compact = re.sub(r"\s+", "", value).upper()
        if 8 <= len(compact) <= 40 and compact.isalnum():
            return compact
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
    raise ValidationFailure(400, "invalid_request", f"that is not a valid {kind}")


def _deny_hash(kind, value):
    return hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()


def _deny_label(kind, value):
    """What the back office shows. A payee account is shown by its last four characters only."""
    return "••••" + value[-4:] if kind == "account" else value


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
            if "list" not in [c["name"] for c in self.db.execute("PRAGMA table_info(deny_list)")]:
                self.db.execute("ALTER TABLE deny_list ADD COLUMN list TEXT NOT NULL DEFAULT 'deny'")  # databases from before the lists
            self.db.commit()
        self.defaults = {"weights": dict(config.WEIGHTS), "bands": json.loads(json.dumps(config.BANDS))}
        self._deny = {}          # (kind, value_hash) -> (list, expires_ms or None), kept in memory for the decision path
        self._load_deny()
        from .velocity import Velocity
        self.velocity = Velocity(self)
        self.custom = customrules.CustomRules(self)
        from .remote import Remote
        self.remote = Remote(self)

    def now_ms(self):
        return int(self.clock() * 1000)

    def note_activity(self, user_id, span_ms, name=None):
        """Adds one batch of time in the app to a customer. The span is capped per batch, so a long gap
        between batches is never counted as use. The first name a device sends is kept; an analyst can rename."""
        now = self.now_ms()
        span = max(0, min(int(span_ms), USAGE_BATCH_CAP_MS))
        with self.lock:
            if self.db.execute("SELECT 1 FROM usage WHERE user_id=?", (user_id,)).fetchone():
                self.db.execute("UPDATE usage SET last_ms=?, active_ms=active_ms+?, batches=batches+1 WHERE user_id=?",
                                (now, span, user_id))
            else:
                self.db.execute("INSERT INTO usage VALUES (?,?,?,?,1)", (user_id, now, now, span))
            if name and name.strip():
                self.db.execute("INSERT OR IGNORE INTO customers VALUES (?,?,?)", (user_id, name.strip(), now))
            self.db.commit()

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

    # feedback (bank-confirmed outcomes)
    def apply_feedback(self, session_id, label, source, note, baselines):
        rows = self.q("SELECT record FROM decisions WHERE session_id=? ORDER BY id DESC LIMIT 1", (session_id,))
        if not rows:
            raise ValidationFailure(404, "unknown_session", "FortGuard has no decision for this session")
        record = json.loads(rows[0]["record"])
        now = self.now_ms()
        self.x("INSERT INTO feedback (session_id, label, decided_level, source, note, time_ms) VALUES (?,?,?,?,?,?)",
               (session_id, label, record["risk_level"], source, note, now))
        removed = baselines.forget(session_id) if label == "FRAUD" else 0
        case = self.q("SELECT id, status FROM cases WHERE session_id=?", (session_id,))
        case_id = case[0]["id"] if case else None
        if label == "FRAUD":
            if case_id is None:  # FortGuard allowed it: a missed fraud. Open a case so it is reviewed.
                cur = self.x("INSERT INTO cases (session_id, created_ms, updated_ms, status, assignee, risk_level, risk_score, "
                             "user_id, device_guid, decision) VALUES (?,?,?,?,?,?,?,?,?,?)",
                             (session_id, now, now, "CONFIRMED_FRAUD", None, record["risk_level"], record["risk_score"],
                              record.get("user_id"), record.get("device_guid"), json.dumps(record)))
                case_id = cur.lastrowid
                self.audit(source or "bank-api", "case_update", f"case:{case_id}",
                           {"before": {"status": None}, "after": {"status": "CONFIRMED_FRAUD"}, "via": "feedback"})
            elif case[0]["status"] != "CONFIRMED_FRAUD":
                self.x("UPDATE cases SET status='CONFIRMED_FRAUD', updated_ms=? WHERE id=?", (now, case_id))
                self.audit(source or "bank-api", "case_update", f"case:{case_id}",
                           {"before": {"status": case[0]["status"]}, "after": {"status": "CONFIRMED_FRAUD"}, "via": "feedback"})
        elif case_id is not None and case[0]["status"] in ("OPEN", "INVESTIGATING"):
            self.x("UPDATE cases SET status='FALSE_POSITIVE', updated_ms=? WHERE id=?", (now, case_id))
            self.audit(source or "bank-api", "case_update", f"case:{case_id}",
                       {"before": {"status": case[0]["status"]}, "after": {"status": "FALSE_POSITIVE"}, "via": "feedback"})
        self.audit(source or "bank-api", "feedback", f"session:{session_id}", {"label": label, "decided": record["risk_level"]})
        return {"session_id": session_id, "label": label, "decided_level": record["risk_level"],
                "case_id": case_id, "baseline_sessions_removed": removed}

    # retention and erasure
    def purge(self, baselines=None):
        """Delete records older than config.RETENTION_DAYS. Confirmed-fraud cases are kept as evidence."""
        now = self.now_ms()
        day = 86_400_000
        r = config.RETENTION_DAYS
        out = {
            "decisions": self.x("DELETE FROM decisions WHERE time_ms < ?", (now - r["decisions"] * day,)).rowcount,
            "cases": self.x("DELETE FROM cases WHERE status <> 'CONFIRMED_FRAUD' AND updated_ms < ?", (now - r["closed_cases"] * day,)).rowcount,
            "feedback": self.x("DELETE FROM feedback WHERE time_ms < ?", (now - r["feedback"] * day,)).rowcount,
            "audit": self.x("DELETE FROM audit WHERE time_ms < ?", (now - r["audit"] * day,)).rowcount,
            "tokens": self.x("DELETE FROM tokens WHERE expires_ms < ?", (now,)).rowcount,
            "velocity_history": self.velocity.purge(now),
        }
        if baselines is not None:
            out["baseline_sessions"] = self.x("DELETE FROM baseline_sessions WHERE time_ms < ?", (now - r["decisions"] * day,)).rowcount
            baselines._invalidate()
        self.x("DELETE FROM notes WHERE case_id NOT IN (SELECT id FROM cases)")
        return out

    def erase_customer(self, user_id, baselines):
        """Right to erasure: remove a customer's behavioral data and decision history.

        Confirmed-fraud cases are kept (evidence, legal obligations); everything else about the
        customer is deleted. The erasure itself is audited without storing anything about the data.
        """
        out = {
            "baseline_sessions": baselines.forget_user(user_id),
            "decisions": self.x("DELETE FROM decisions WHERE json_extract(record, '$.user_id') = ?", (user_id,)).rowcount,
            "cases": self.x("DELETE FROM cases WHERE user_id = ? AND status <> 'CONFIRMED_FRAUD'", (user_id,)).rowcount,
            "kept_fraud_cases": self.q("SELECT COUNT(*) AS n FROM cases WHERE user_id = ?", (user_id,))[0]["n"],
            "velocity_history": self.velocity.erase(user_id),
            "consent_records": self.remote.erase(user_id),
        }
        self.x("DELETE FROM notes WHERE case_id NOT IN (SELECT id FROM cases)")
        return out

    # rules
    # --- deny list ---------------------------------------------------------------------------------

    def _load_deny(self):
        rows = self.q("SELECT kind, value_hash, expires_ms, list FROM deny_list")
        self._deny = {(r["kind"], r["value_hash"]): (r["list"], r["expires_ms"]) for r in rows}

    def deny_add(self, kind, value, reason, actor, expires_ms=None, list_name="deny"):
        value = _deny_value(kind, value)
        if list_name != "deny" and kind != "account":
            raise ValidationFailure(400, "invalid_request", f"only payee accounts can go on the {LIST_TEXT[list_name]}")
        try:
            self.x("INSERT INTO deny_list (kind, value_hash, label, reason, added_by, created_ms, expires_ms, list) VALUES (?,?,?,?,?,?,?,?)",
                   (kind, _deny_hash(kind, value), _deny_label(kind, value), reason, actor, self.now_ms(), expires_ms, list_name))
        except sqlite3.IntegrityError:
            on = self.q("SELECT list FROM deny_list WHERE kind=? AND value_hash=?", (kind, _deny_hash(kind, value)))[0]["list"]
            raise ValidationFailure(409, "already_listed", f"that {kind} is already on the {LIST_TEXT[on]}") from None
        self._load_deny()
        return self.q("SELECT * FROM deny_list WHERE kind=? AND value_hash=?", (kind, _deny_hash(kind, value)))[0]

    def deny_remove(self, entry_id):
        rows = self.q("SELECT * FROM deny_list WHERE id=?", (entry_id,))
        if not rows:
            return None
        self.x("DELETE FROM deny_list WHERE id=?", (entry_id,))
        self._load_deny()
        return rows[0]

    def deny_entries(self):
        now = self.now_ms()
        return [{"id": r["id"], "kind": r["kind"], "list": r["list"], "label": r["label"], "reason": r["reason"],
                 "added_by": r["added_by"], "created_ms": r["created_ms"], "expires_ms": r["expires_ms"],
                 "expired": r["expires_ms"] is not None and r["expires_ms"] <= now}
                for r in self.q("SELECT * FROM deny_list ORDER BY id DESC")]

    def _listed(self, kind, value, now):
        """Which list this value is on right now, or None."""
        try:
            entry = self._deny.get((kind, _deny_hash(kind, _deny_value(kind, value))))
        except ValidationFailure:
            return None
        if entry is None or (entry[1] is not None and entry[1] <= now):
            return None
        return entry[0]

    def deny_match(self, **values):
        """Which kinds of this request are on the deny list and not expired, e.g. ("account",)."""
        if not self._deny:
            return ()
        now = self.now_ms()
        return tuple(kind for kind, value in values.items() if value and self._listed(kind, value, now) == "deny")

    def payee_lists(self, account):
        """The mule or allow list a payee account is on: ("mule",), ("allow",) or ()."""
        if not self._deny or not account:
            return ()
        on = self._listed("account", account, self.now_ms())
        return (on,) if on in ("mule", "allow") else ()

    def load_rules(self):
        """Apply rule settings saved earlier, if any."""
        rows = self.q("SELECT value FROM settings WHERE key='rules'")
        if rows:
            saved = json.loads(rows[0]["value"])
            config.WEIGHTS.update({k: v for k, v in saved.get("weights", {}).items() if k in config.WEIGHTS})
            if "bands" in saved:
                config.BANDS["default"].update(saved["bands"])
            for journey in [j for j in config.BANDS if j != "default"]:
                del config.BANDS[journey]
            for journey, bands in saved.get("journey_bands", {}).items():
                if journey in config.EVENT_TYPES:
                    config.BANDS[journey] = dict(bands)

    def save_rules(self):
        self.x("INSERT OR REPLACE INTO settings VALUES ('rules', ?)",
               (json.dumps({"weights": config.WEIGHTS, "bands": config.BANDS["default"],
                            "journey_bands": {j: b for j, b in config.BANDS.items() if j != "default"}}),))


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

CUSTOMER_SCAN_LIMIT = 5000  # newest decisions searched when grouping by customer
USAGE_BATCH_CAP_MS = 60_000  # no batch counts more than a minute of time in the app


def _latest_by_device(bo):
    """The newest decision per device, and the customers seen on each device."""
    latest, users = {}, {}
    for rec in _recent_decisions(bo):  # newest first
        guid = rec.get("device_guid")
        if guid:
            latest.setdefault(guid, rec)
            users.setdefault(guid, set()).add(rec["user_id"])
    return latest, users


def _usage_of(bo, user_id):
    row = bo.q("SELECT first_ms, last_ms, active_ms, batches FROM usage WHERE user_id=?", (user_id,))
    return dict(row[0]) if row else {"first_ms": None, "last_ms": None, "active_ms": 0, "batches": 0}


def _maturity(status):
    """Share of the profile built so far: learned sessions against the number needed before the profile is used."""
    return round(min(1.0, status["sessions"] / status["required"]), 3)


def _coverage(latest):
    """Which of the sensors the app reads reported data in the newest session. A sensor the phone lacks shows as not reporting."""
    captured = (latest or {}).get("captured") or {}
    reporting = [n for n in config.SENSOR_NAMES if captured.get(n, 0) > 0]
    return {"reporting": len(reporting), "of": len(config.SENSOR_NAMES), "names": reporting}


def _recent_decisions(bo):
    rows = bo.q("SELECT record FROM decisions ORDER BY id DESC LIMIT ?", (CUSTOMER_SCAN_LIMIT,))
    return [json.loads(r["record"]) for r in rows]


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
        seen = Counter()  # decisions in which each signal delivered at least one sample
        cpm_buckets = Counter()
        ml_scored = ml_flagged = 0
        for r in rows:
            rec = json.loads(r["record"])
            ml = rec.get("ml") or {}
            ml_scored += ml.get("status") == "ACTIVE"
            ml_flagged += bool(ml.get("anomalous"))
            for code in rec.get("reason_codes", []):
                reasons[code] += 1
            hourly[(r["time_ms"] // 3_600_000) * 3_600_000][r["risk_level"]] += 1
            for name, n in (rec.get("captured") or {}).items():
                if n:
                    seen[name] += 1
            cpm = (rec.get("features") or {}).get("ft_typing_speed_cpm")
            if cpm is not None:
                cpm_buckets[_cpm_bucket(cpm)] += 1
        total = len(rows)
        statuses = Counter(r["status"] for r in bo.q("SELECT status FROM cases"))
        return jsonify({
            "last_24h": {"total": len(rows), "ALLOW": levels["ALLOW"], "STEP_UP": levels["STEP_UP"], "BLOCK": levels["BLOCK"]},
            "top_reasons": reasons.most_common(8),
            "bands": dict(config.BANDS["default"]),
            # Decisions the machine-learning model was mature enough to score, and how many it flagged.
            "ml": {"scored": ml_scored, "flagged": ml_flagged},
            "hourly": [{"hour_ms": h, **hourly[h]} for h in
                       range((since // 3_600_000 + 1) * 3_600_000, bo.now_ms() + 1, 3_600_000)] if rows else [],
            "cases": {s: statuses[s] for s in CASE_STATUSES},
            "devices": {"total": len(registry.all()), "revoked": sum(1 for d in registry.all() if d.status != "ACTIVE")},
            "feedback": feedback_summary(bo),
            "coverage": [{"signal": k, "decisions": seen[k], "share": round(seen[k] / total, 3) if total else 0}
                         for k in SIGNAL_KEYS] if total else [],
            "typing_speed": [{"label": label, "decisions": cpm_buckets[label]} for label in CPM_LABELS],
            "time_in_app_ms": sum(r["active_ms"] for r in bo.q("SELECT active_ms FROM usage")),
            "devices_by_model": [{"model": m, "devices": n} for m, n in Counter(
                ((rec.get("environment") or {}).get("device_model") or "Unknown")
                for rec in _latest_by_device(bo)[0].values()).most_common(8)],
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
        if changes.get("status") == "CONFIRMED_FRAUD":
            from flask import current_app
            current_app.fortguard_baselines.forget(row["session_id"])
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
        latest, users = _latest_by_device(bo)
        rows = []
        for d in registry.all():
            rec = latest.get(d.device_guid) or {}
            env = rec.get("environment") or {}
            rows.append({
                "device_guid": d.device_guid, "app_id": d.app_id, "platform": d.platform, "integrity_level": d.integrity,
                "status": d.status, "key_version": d.key_version, "key_sha256": d.key_sha256[:16],
                "enrolled_at_ms": int(d.enrolled_at * 1000),
                "model": env.get("device_model"), "os": env.get("os"), "os_version": env.get("os_version"),
                "owner_enrolled": bool(d.owner_key_sha256), "last_seen_ms": rec.get("time_ms"),
                "last_ip": (rec.get("network") or {}).get("ip"),
                "customers": sorted(users.get(d.device_guid, ()))[:5],
            })
        rows.sort(key=lambda r: -r["enrolled_at_ms"])
        return jsonify({"devices": rows})

    @app.post("/v1/bo/devices/<device_guid>/revoke")
    def bo_device_revoke(device_guid):
        user = need("analyst")
        if not registry.revoke(device_guid):
            raise ValidationFailure(404, "unknown_device", "no such device")
        bo.audit(user["username"], "device_revoke", f"device:{device_guid}", None)
        return jsonify({"device_guid": device_guid, "status": "REVOKED"})

    # deny list
    @app.get("/v1/bo/deny-list")
    def bo_deny_list():
        need("viewer")
        return jsonify({"entries": bo.deny_entries(), "kinds": list(DENY_KINDS), "lists": list(LISTS)})

    @app.post("/v1/bo/deny-list")
    def bo_deny_add():
        user = need("analyst")
        data = body()
        if set(data) - {"kind", "value", "reason", "expires_days", "list"}:
            raise ValidationFailure(400, "unknown_field", "send kind, value, reason and optionally expires_days and list")
        list_name = data.get("list", "deny")
        if list_name not in LISTS:
            raise ValidationFailure(400, "invalid_request", f"list must be one of {list(LISTS)}")
        if data.get("kind") not in DENY_KINDS:
            raise ValidationFailure(400, "invalid_request", f"kind must be one of {list(DENY_KINDS)}")
        reason = data.get("reason")
        if not isinstance(reason, str) or not 3 <= len(reason.strip()) <= 200 or any(ord(c) < 32 for c in reason):
            raise ValidationFailure(400, "invalid_request", "give a reason of 3 to 200 characters")
        days = data.get("expires_days")
        if days is not None and (isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= DENY_MAX_DAYS):
            raise ValidationFailure(400, "invalid_request", f"expires_days must be a whole number from 1 to {DENY_MAX_DAYS}")
        expires = bo.now_ms() + days * 86_400_000 if days else None
        row = bo.deny_add(data["kind"], data.get("value"), reason.strip(), user["username"], expires, list_name)
        bo.audit(user["username"], "deny_add", f"{row['kind']}:{row['label']}",
                 {"list": list_name, "reason": row["reason"], "expires_days": days})
        return jsonify({"entries": bo.deny_entries()}), 201

    @app.delete("/v1/bo/deny-list/<int:entry_id>")
    def bo_deny_remove(entry_id):
        user = need("analyst")
        row = bo.deny_remove(entry_id)
        if row is None:
            raise ValidationFailure(404, "unknown_entry", "no such deny-list entry")
        bo.audit(user["username"], "deny_remove", f"{row['kind']}:{row['label']}", {"list": row["list"], "reason": row["reason"]})
        return jsonify({"entries": bo.deny_entries()})

    # rules
    def rules_view():
        return {"weights": dict(config.WEIGHTS), "bands": dict(config.BANDS["default"]),
                "journey_bands": {j: dict(b) for j, b in config.BANDS.items() if j != "default"},
                "journeys": list(config.EVENT_TYPES), "defaults": bo.defaults, "score_max": config.SCORE_MAX}

    @app.get("/v1/bo/rules")
    def bo_rules():
        need("viewer")
        return jsonify(rules_view())

    @app.put("/v1/bo/rules")
    def bo_rules_update():
        user = need("admin")
        data = body()
        journey_bands = validate_journey_bands(data.pop("journey_bands", None))
        weights, new_bands = validate_rules(data)
        before = {"weights": {k: config.WEIGHTS[k] for k in weights}, "bands": dict(config.BANDS["default"])}
        after = {"weights": weights, "bands": new_bands}
        config.WEIGHTS.update(weights)
        config.BANDS["default"].update(new_bands)
        if journey_bands is not None:
            before["journey_bands"] = {j: dict(b) for j, b in config.BANDS.items() if j != "default"}
            after["journey_bands"] = journey_bands
            for journey in [j for j in config.BANDS if j != "default"]:
                del config.BANDS[journey]
            config.BANDS.update({j: dict(b) for j, b in journey_bands.items()})
        bo.save_rules()
        bo.audit(user["username"], "rules_update", "rules", {"before": before, "after": after})
        return jsonify(rules_view())

    @app.post("/v1/bo/rules/preview")
    def bo_rules_preview():
        """Replay recent decisions under draft rules, without changing anything."""
        need("viewer")
        weights, new_bands = validate_rules(body())
        limit = _limit(request.args.get("limit"), 2000)
        return jsonify(replay(bo, weights, new_bands, limit))

    # the bank's own rules (customrules.py): shadow first, a second person for anything live
    custom = bo.custom

    def rule_change(action, rule, extra=None):
        bo.audit(g.user["username"], action, "rule:" + rule["name"], extra)
        return jsonify({"rule": rule, "rules": custom.all()})

    @app.get("/v1/bo/custom-rules")
    def bo_custom_rules():
        need("viewer")
        variables = [{"name": n, "type": t, "about": d} for n, (t, d) in rulelang.VARIABLES.items()]
        return jsonify({"rules": custom.all(), "variables": variables, "floors": list(customrules.FLOORS),
                        "journeys": list(config.EVENT_TYPES), "report": customrules.shadow_report(bo)})

    @app.post("/v1/bo/custom-rules")
    def bo_custom_rule_create():
        user = need("analyst")
        rule = custom.create(customrules.validate(body(), need_name=True), user["username"])
        bo.audit(user["username"], "rule_create", "rule:" + rule["name"],
                 {"expression": rule["expression"], "points": rule["points"], "floor": rule["floor"],
                  "asked_to_go_live": rule["pending"] is not None})
        return jsonify({"rule": rule, "rules": custom.all()}), 201

    @app.post("/v1/bo/custom-rules/test")
    def bo_custom_rule_test():
        """Check a draft condition and run it over stored decisions. Changes nothing."""
        need("viewer")
        data = body()
        draft = customrules.validate({"description": "draft", **{k: data[k] for k in ("expression", "points", "floor", "journeys") if k in data}},
                                     need_name=False)
        tree = rulelang.compile_rule(draft["expression"])
        result = customrules.backtest(bo, draft["expression"], draft["journeys"], draft["points"], draft["floor"],
                                      _limit(request.args.get("limit"), 2000))
        result["names_used"] = sorted(rulelang.names_used(tree))
        return jsonify(result)

    @app.put("/v1/bo/custom-rules/<int:rule_id>")
    def bo_custom_rule_update(rule_id):
        user = need("analyst")
        before = custom.view(custom.get(rule_id))
        rule, outcome = custom.update(rule_id, customrules.validate(body(), need_name=False), user["username"])
        return rule_change("rule_update" if outcome == "applied" else "rule_request", rule,
                           {"outcome": outcome, "before": {k: before[k] for k in customrules.FIELDS},
                            "asked": rule["pending"] or {k: rule[k] for k in customrules.FIELDS}})

    @app.post("/v1/bo/custom-rules/<int:rule_id>/<action>")
    def bo_custom_rule_action(rule_id, action):
        if action not in ("approve", "reject", "retire", "restore"):
            raise ValidationFailure(404, "not_found", "no such endpoint")
        user = need("admin")
        if action == "approve":
            rule, pending = custom.approve(rule_id, user["username"])
            return rule_change("rule_approve", rule, {"requested_by": pending["requested_by"], "mode": rule["mode"]})
        if action == "reject":
            rule, pending = custom.reject(rule_id, user["username"])
            return rule_change("rule_reject", rule, {"requested_by": pending["requested_by"]})
        return rule_change("rule_" + action, custom.retire(rule_id, user["username"], retired=action == "retire"))

    # consent wording and the signed configuration the SDK obeys (remote.py)
    @app.get("/v1/bo/consent")
    def bo_consent():
        need("viewer")
        from .remote import CONSENT_GROUPS
        return jsonify({"texts": bo.remote.all_texts(), "groups": list(CONSENT_GROUPS)})

    @app.post("/v1/bo/consent")
    def bo_consent_publish():
        user = need("admin")
        data = body()
        if set(data) - {"group", "lang", "text"}:
            raise ValidationFailure(400, "unknown_field", "send group, lang and text")
        out = bo.remote.publish_text(data.get("group"), data.get("lang"), data.get("text"), user["username"])
        bo.audit(user["username"], "consent_publish", f"{out['group']}:{out['lang']}", {"version": out["version"]})
        return jsonify({"published": out, "texts": bo.remote.all_texts()}), 201

    def config_view():
        from .remote import COLLECT_KINDS, COLLECT_TEXT
        return {"config": bo.remote.config, "key": bo.remote.public_key(),
                "kinds": [{"name": k, "about": COLLECT_TEXT[k]} for k in COLLECT_KINDS]}

    @app.get("/v1/bo/config")
    def bo_config():
        need("viewer")
        return jsonify(config_view())

    @app.put("/v1/bo/config")
    def bo_config_update():
        user = need("admin")
        before, after = bo.remote.update_config(body())
        if after["version"] != before["version"]:
            bo.audit(user["username"], "config_update", "remote_config",
                     {"before": {k: before[k] for k in ("collect", "flush_interval_ms")},
                      "after": {k: after[k] for k in ("collect", "flush_interval_ms")}, "version": after["version"]})
        return jsonify(config_view())

    # retention and erasure
    @app.post("/v1/bo/maintenance/purge")
    def bo_purge():
        user = need("admin")
        from flask import current_app
        out = bo.purge(current_app.fortguard_baselines)
        bo.audit(user["username"], "purge", "retention", out)
        return jsonify({"deleted": out, "retention_days": config.RETENTION_DAYS})

    @app.post("/v1/bo/customers/<user_id>/erase")
    def bo_erase(user_id):
        user = need("admin")
        if not 1 <= len(user_id) <= 64:
            raise ValidationFailure(400, "invalid_request", "bad customer id")
        from flask import current_app
        out = bo.erase_customer(user_id, current_app.fortguard_baselines)
        bo.x("DELETE FROM customers WHERE user_id=?", (user_id,))
        bo.x("DELETE FROM usage WHERE user_id=?", (user_id,))
        bo.audit(user["username"], "customer_erase", f"customer:{user_id}", out)
        return jsonify({"user_id": user_id, "deleted": out})

    # customers: everything the decision log holds for one user id, grouped for the portal
    def _check_user_id(user_id):
        if not 1 <= len(user_id) <= 64:
            raise ValidationFailure(400, "invalid_request", "bad customer id")

    def _owner_status(baselines, user_id):
        prof = baselines.profile(user_id)
        n = prof["sessions"]
        status = "MATURE" if n >= config.BASELINE_MIN_SESSIONS else ("LEARNING" if n else "NONE")
        return {"status": status, "sessions": n, "required": config.BASELINE_MIN_SESSIONS, "features": prof["stats"]}

    def _ml_status(baselines, user_id):
        """Where this customer's machine-learning model stands: still learning, or active and on what."""
        prof = baselines.profile(user_id)
        model, n = prof["ml"], prof["sessions"]
        return {"model": mlmodel.MODEL_NAME, "status": "ACTIVE" if model else ("LEARNING" if n else "NONE"),
                "sessions": model.sessions if model else n, "required": config.ML_MIN_SESSIONS,
                "features": list(model.names) if model else []}

    @app.get("/v1/bo/customers")
    def bo_customers():
        need("viewer")
        from flask import current_app
        names = {r["user_id"]: r["display_name"] for r in bo.q("SELECT user_id, display_name FROM customers")}
        groups = {}
        for rec in _recent_decisions(bo):
            g = groups.setdefault(rec["user_id"], {"user_id": rec["user_id"], "sessions": 0, "last_ms": 0,
                                                   "devices": set(), "levels": Counter(), "max_risk": 0})
            g["sessions"] += 1
            g["last_ms"] = max(g["last_ms"], rec.get("time_ms") or 0)
            if rec.get("device_guid"):
                g["devices"].add(rec["device_guid"])
            g["levels"][rec["risk_level"]] += 1
            g["max_risk"] = max(g["max_risk"], rec.get("risk_score") or 0)
        for r in bo.q("SELECT user_id FROM usage"):
            groups.setdefault(r["user_id"], {"user_id": r["user_id"], "sessions": 0, "last_ms": 0,
                                             "devices": set(), "levels": Counter(), "max_risk": 0})
        rows = []
        for uid, g in groups.items():
            rows.append({"user_id": uid, "display_name": names.get(uid), "sessions": g["sessions"],
                         "devices": len(g["devices"]), "last_ms": g["last_ms"], "max_risk": g["max_risk"],
                         "levels": {k: g["levels"][k] for k in ("ALLOW", "STEP_UP", "BLOCK")},
                         "owner": _owner_status(current_app.fortguard_baselines, uid)["status"],
                         "maturity": _maturity(_owner_status(current_app.fortguard_baselines, uid)),
                         "ml": _ml_status(current_app.fortguard_baselines, uid)["status"],
                         "active_ms": _usage_of(bo, uid)["active_ms"]})
        rows.sort(key=lambda r: -r["last_ms"])
        return jsonify({"customers": rows[:200]})

    @app.get("/v1/bo/customers/<user_id>")
    def bo_customer(user_id):
        need("viewer")
        _check_user_id(user_id)
        from flask import current_app
        recs = sorted((r for r in _recent_decisions(bo) if r["user_id"] == user_id),
                      key=lambda r: r.get("time_ms") or 0, reverse=True)
        name = bo.q("SELECT display_name FROM customers WHERE user_id=?", (user_id,))
        if not recs and not name:
            raise ValidationFailure(404, "not_found", "no decisions for this customer")
        devices = {}
        for rec in recs:  # newest first, so the first record seen for a device is its latest
            guid = rec.get("device_guid")
            if not guid:
                continue
            if guid not in devices:
                dev = registry.get(guid)
                env = rec.get("environment") or {}
                devices[guid] = {
                    "device_guid": guid, "platform": rec.get("device_platform") or (dev.platform if dev else None),
                    "model": env.get("device_model"), "os": env.get("os"), "os_version": env.get("os_version"),
                    "integrity_level": rec.get("device_integrity"),
                    "status": dev.status if dev else "UNKNOWN",
                    "owner_enrolled": bool(dev and dev.owner_key_sha256),
                    "last_seen_ms": rec.get("time_ms"), "first_seen_ms": rec.get("time_ms"),
                }
            else:
                devices[guid]["first_seen_ms"] = rec.get("time_ms")
        return jsonify({
            "user_id": user_id,
            "display_name": name[0]["display_name"] if name else None,
            "owner_profile": _owner_status(current_app.fortguard_baselines, user_id),
            "ml_model": _ml_status(current_app.fortguard_baselines, user_id),
            "devices": list(devices.values()),
            "sessions": [{"time_ms": r.get("time_ms"), "session_id": r["session_id"], "event_type": r.get("event_type"),
                          "amount": r.get("amount"), "currency": r.get("currency"), "risk_level": r["risk_level"],
                          "risk_score": r["risk_score"], "action": r.get("action_recommended"),
                          "reason_codes": r.get("reason_codes") or [],
                          "device_guid": r.get("device_guid")} for r in recs[:100]],
            "latest": recs[0] if recs else None,  # full numbers behind the newest decision
            "usage": _usage_of(bo, user_id),
            "consents": bo.remote.consent_history(user_id),
            "maturity": _maturity(_owner_status(current_app.fortguard_baselines, user_id)),
            "coverage": _coverage(recs[0] if recs else None),
        })

    @app.post("/v1/bo/customers/<user_id>/name")
    def bo_customer_name(user_id):
        user = need("analyst")
        _check_user_id(user_id)
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            raise ValidationFailure(400, "invalid_json", "body must be a JSON object")
        name = body.get("display_name")
        if name is not None and (not isinstance(name, str) or len(name.strip()) > 80
                                 or any(ord(ch) < 32 for ch in name)):
            raise ValidationFailure(400, "invalid_request", "display_name must be plain text up to 80 characters")
        name = (name or "").strip()
        if name:
            bo.x("INSERT OR REPLACE INTO customers VALUES (?,?,?)", (user_id, name, bo.now_ms()))
        else:
            bo.x("DELETE FROM customers WHERE user_id=?", (user_id,))
        bo.audit(user["username"], "customer_name", f"customer:{user_id}", {"named": bool(name)})
        return jsonify({"user_id": user_id, "display_name": name or None})

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
            try:
                status, body = run_session(transport, build_session(name, int(clock() * 1000), seed0 + i), now_ms=int(clock() * 1000))
            except RuntimeError:  # the enrolment rate limit, after several runs in a row
                if results:
                    bo.audit(user["username"], "dev_simulate", "scenarios", {"count": len(results)})
                raise ValidationFailure(429, "rate_limited", "Sample scenarios were run several times in a row. "
                                        f"{len(results)} sessions were added this time. Wait a minute and try again.")
            results.append({"scenario": name, "risk_level": body.get("risk_level"), "risk_score": body.get("risk_score")})
        bo.audit(user["username"], "dev_simulate", "scenarios", {"count": len(results)})
        return jsonify({"results": results})


def validate_rules(data):
    """Check a rules change; returns (weights to change, the complete new default bands)."""
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
    return weights, new_bands


def validate_journey_bands(data):
    """Bands for single journeys: {journey: {step_up_from, block_from}}. A journey left out uses the default."""
    if data is None:
        return None
    if not isinstance(data, dict):
        raise ValidationFailure(400, "invalid_request", "journey_bands must be an object")
    out = {}
    for journey, bands in data.items():
        if journey not in config.EVENT_TYPES:
            raise ValidationFailure(400, "invalid_request", f"unknown journey {journey}")
        if not isinstance(bands, dict) or set(bands) != {"step_up_from", "block_from"} or any(
                isinstance(v, bool) or not isinstance(v, int) for v in bands.values()):
            raise ValidationFailure(400, "invalid_request", f"{journey} needs whole numbers for step_up_from and block_from")
        if not 1 <= bands["step_up_from"] < bands["block_from"] <= config.SCORE_MAX:
            raise ValidationFailure(400, "invalid_request", f"{journey}: bands must satisfy 1 <= step_up_from < block_from <= 1000")
        out[journey] = {"step_up_from": bands["step_up_from"], "block_from": bands["block_from"]}
    return out


def rescore(record, weights, bands):
    """Score one stored decision again from its reason codes under draft weights and bands.

    Uses the reasons that fired at the time; it does not recompute behavior. Degraded decisions
    are returned unchanged because their score does not come from rule weights.
    """
    from .scoring import FORCE_STEP_UP_REASONS

    if record.get("degraded") or str(record.get("signals_used")) == "TRANSACTION_ONLY":
        return record["risk_score"], record["risk_level"]
    reasons = [item["reason"] for item in record.get("score_breakdown", []) if item["reason"] in config.WEIGHTS]
    w = dict(config.WEIGHTS); w.update(weights)
    custom = sum(item["points"] for item in record.get("score_breakdown", []) if item.get("custom"))  # as decided at the time
    score = min(config.SCORE_MAX, sum(w[r] for r in reasons) + custom)
    if score < config.FORCE_STEP_UP_MIN_SCORE and any(r in reasons for r in FORCE_STEP_UP_REASONS):
        score = config.FORCE_STEP_UP_MIN_SCORE
    level = "BLOCK" if score >= bands["block_from"] else ("STEP_UP" if score >= bands["step_up_from"] else "ALLOW")
    return score, level


def replay(bo, weights, bands, limit=2000):
    rows = bo.q("SELECT record FROM decisions ORDER BY id DESC LIMIT ?", (limit,))
    labels = {r["session_id"]: r["label"] for r in bo.q("SELECT session_id, label FROM feedback ORDER BY id")}
    levels = ("ALLOW", "STEP_UP", "BLOCK")
    before = {lv: 0 for lv in levels}
    after = {lv: 0 for lv in levels}
    moves = {}
    changed = []
    outcome = {"fraud": {"flagged_before": 0, "flagged_after": 0, "total": 0},
               "genuine": {"challenged_before": 0, "challenged_after": 0, "total": 0}}
    for row in rows:
        rec = json.loads(row["record"])
        old_level = rec["risk_level"]
        new_score, new_level = rescore(rec, weights, bands)
        before[old_level] += 1
        after[new_level] += 1
        if new_level != old_level:
            key = f"{old_level}->{new_level}"
            moves[key] = moves.get(key, 0) + 1
            if len(changed) < 25:
                changed.append({"session_id": rec["session_id"], "user_id": rec.get("user_id"),
                                "before": {"score": rec["risk_score"], "level": old_level},
                                "after": {"score": new_score, "level": new_level},
                                "reasons": [i["reason"] for i in rec.get("score_breakdown", [])]})
        label = labels.get(rec["session_id"])
        if label == "FRAUD":
            o = outcome["fraud"]; o["total"] += 1
            o["flagged_before"] += old_level != "ALLOW"; o["flagged_after"] += new_level != "ALLOW"
        elif label == "GENUINE":
            o = outcome["genuine"]; o["total"] += 1
            o["challenged_before"] += old_level != "ALLOW"; o["challenged_after"] += new_level != "ALLOW"
    return {"replayed": len(rows), "before": before, "after": after, "moves": moves,
            "changed": changed, "changed_total": sum(moves.values()), "labeled_outcomes": outcome,
            "note": "Replays the reasons recorded at decision time under the draft rules; behavior is not recomputed."}


def feedback_summary(bo):
    """Outcomes the bank confirmed, against what FortGuard decided at the time."""
    rows = bo.q("SELECT label, decided_level FROM feedback")
    fraud = [r for r in rows if r["label"] == "FRAUD"]
    genuine = [r for r in rows if r["label"] == "GENUINE"]
    return {
        "fraud_reported": len(fraud),
        "fraud_caught": sum(1 for r in fraud if r["decided_level"] in ("STEP_UP", "BLOCK")),
        "fraud_missed": sum(1 for r in fraud if r["decided_level"] == "ALLOW"),
        "genuine_reported": len(genuine),
        "genuine_challenged": sum(1 for r in genuine if r["decided_level"] in ("STEP_UP", "BLOCK")),
    }


def _limit(value, default):
    if value is None:
        return default
    try:
        return max(1, min(int(value), 1000))
    except ValueError:
        raise ValidationFailure(400, "invalid_request", "limit must be a number")
