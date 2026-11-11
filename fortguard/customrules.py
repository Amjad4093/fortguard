"""The bank's own rules, written in the expression language in rulelang.py.

A rule has a condition, points to add, an optional floor (at least STEP_UP, or at least BLOCK) and the
journeys it applies to. It runs in one of two modes:

    shadow  evaluated on every decision and recorded, but it never changes a score. This is how a new
            rule is tried on real traffic first.
    live    its points and floor are applied.

Four-eyes control: anything that makes a rule affect customers needs a second person. A new rule always
starts in shadow. Asking for it to go live, or changing a rule that is already live, is stored as a
pending request, and an admin other than the one who asked must approve it. Shadow rules can be edited
freely because they cannot affect a customer. Retiring a rule is immediate and audited.
"""

import json
import re

from . import config, rulelang
from .schema import ValidationFailure

NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,39}$")
FLOORS = ("NONE", "STEP_UP", "BLOCK")
MODES = ("shadow", "live")
MAX_RULES = 200
FIELDS = ("description", "expression", "points", "floor", "journeys", "mode")

SCHEMA = """
CREATE TABLE IF NOT EXISTS custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, description TEXT NOT NULL,
    expression TEXT NOT NULL, points INTEGER NOT NULL, floor TEXT NOT NULL, journeys TEXT NOT NULL,
    mode TEXT NOT NULL, retired INTEGER NOT NULL DEFAULT 0, pending TEXT,
    created_by TEXT NOT NULL, created_ms INTEGER NOT NULL, updated_by TEXT NOT NULL, updated_ms INTEGER NOT NULL,
    approved_by TEXT, approved_ms INTEGER);
"""


def code_for(name):
    """The reason code a live rule adds to a decision."""
    return "CUSTOM_" + name.upper()


def _bad(message):
    raise ValidationFailure(400, "invalid_rule", message)


def validate(data, need_name):
    """A rule definition from the back office, checked. Returns the cleaned definition."""
    allowed = set(FIELDS) | ({"name"} if need_name else set())
    if not isinstance(data, dict) or set(data) - allowed:
        _bad("a rule may only carry " + ", ".join(sorted(allowed)))
    out = {}
    if need_name:
        if not isinstance(data.get("name"), str) or not NAME_RE.match(data["name"]):
            _bad("name must be 3 to 40 lower-case letters, digits or underscores, starting with a letter")
        out["name"] = data["name"]
    description = data.get("description")
    if not isinstance(description, str) or not 3 <= len(description.strip()) <= 200 or any(ord(c) < 32 for c in description):
        _bad("describe the rule in 3 to 200 characters")
    out["description"] = description.strip()
    try:
        rulelang.compile_rule(data.get("expression"))
    except rulelang.RuleError as exc:
        _bad(str(exc))
    out["expression"] = data["expression"].strip()
    points = data.get("points", 0)
    if isinstance(points, bool) or not isinstance(points, int) or not 0 <= points <= config.SCORE_MAX:
        _bad(f"points must be a whole number from 0 to {config.SCORE_MAX}")
    out["points"] = points
    out["floor"] = data.get("floor", "NONE")
    if out["floor"] not in FLOORS:
        _bad(f"floor must be one of {list(FLOORS)}")
    if out["points"] == 0 and out["floor"] == "NONE":
        _bad("give the rule points, a floor, or both: otherwise it can never change a decision")
    journeys = data.get("journeys", [])
    if not isinstance(journeys, list) or any(j not in config.EVENT_TYPES for j in journeys) or len(set(journeys)) != len(journeys):
        _bad(f"journeys must be a list from {list(config.EVENT_TYPES)}; leave it empty for every journey")
    out["journeys"] = journeys
    out["mode"] = data.get("mode", "shadow")
    if out["mode"] not in MODES:
        _bad("mode must be shadow or live")
    return out


class CustomRules:
    def __init__(self, bo):
        self.bo = bo
        with bo.lock:
            bo.db.executescript(SCHEMA)
            bo.db.commit()
        self._active = []
        self._load()

    def _load(self):
        active = []
        for row in self.bo.q("SELECT * FROM custom_rules WHERE retired=0 ORDER BY id"):
            try:
                tree = rulelang.compile_rule(row["expression"])
            except rulelang.RuleError:   # a variable was removed from the language since the rule was saved
                continue
            active.append({"name": row["name"], "points": row["points"], "floor": row["floor"], "mode": row["mode"],
                           "journeys": frozenset(json.loads(row["journeys"])), "tree": tree})
        self._active = active

    # --- reading ---------------------------------------------------------------------------------------
    def view(self, row):
        return {"id": row["id"], "name": row["name"], "code": code_for(row["name"]), "description": row["description"],
                "expression": row["expression"], "points": row["points"], "floor": row["floor"],
                "journeys": json.loads(row["journeys"]), "mode": row["mode"], "retired": bool(row["retired"]),
                "pending": json.loads(row["pending"]) if row["pending"] else None,
                "created_by": row["created_by"], "created_ms": row["created_ms"], "updated_by": row["updated_by"],
                "updated_ms": row["updated_ms"], "approved_by": row["approved_by"], "approved_ms": row["approved_ms"]}

    def all(self):
        return [self.view(r) for r in self.bo.q("SELECT * FROM custom_rules ORDER BY retired, id DESC")]

    def get(self, rule_id):
        rows = self.bo.q("SELECT * FROM custom_rules WHERE id=?", (rule_id,))
        if not rows:
            raise ValidationFailure(404, "unknown_rule", "no such rule")
        return rows[0]

    # --- changing ----------------------------------------------------------------------------------------
    def create(self, definition, actor):
        if len(self.bo.q("SELECT 1 FROM custom_rules")) >= MAX_RULES:
            _bad(f"there are already {MAX_RULES} rules; retire one first")
        if self.bo.q("SELECT 1 FROM custom_rules WHERE name=?", (definition["name"],)):
            raise ValidationFailure(409, "name_taken", "a rule with that name already exists")
        now = self.bo.now_ms()
        wants_live = definition["mode"] == "live"
        pending = json.dumps(self._request(definition, actor, now)) if wants_live else None
        self.bo.x("INSERT INTO custom_rules (name, description, expression, points, floor, journeys, mode, pending, "
                  "created_by, created_ms, updated_by, updated_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                  (definition["name"], definition["description"], definition["expression"], definition["points"],
                   definition["floor"], json.dumps(definition["journeys"]), "shadow", pending, actor, now, actor, now))
        self._load()
        return self.view(self.bo.q("SELECT * FROM custom_rules WHERE name=?", (definition["name"],))[0])

    @staticmethod
    def _request(definition, actor, now):
        return {**{k: definition[k] for k in FIELDS}, "requested_by": actor, "requested_ms": now}

    def update(self, rule_id, definition, actor):
        """Applied at once when the rule is, and stays, in shadow. Otherwise it waits for a second person."""
        row = self.get(rule_id)
        if row["retired"]:
            _bad("this rule is retired; restore it first")
        now = self.bo.now_ms()
        if row["mode"] == "shadow" and definition["mode"] == "shadow":
            self._apply(rule_id, definition, actor, now, approved_by=None)
            return self.view(self.get(rule_id)), "applied"
        self.bo.x("UPDATE custom_rules SET pending=?, updated_by=?, updated_ms=? WHERE id=?",
                  (json.dumps(self._request(definition, actor, now)), actor, now, rule_id))
        return self.view(self.get(rule_id)), "pending"

    def _apply(self, rule_id, definition, actor, now, approved_by):
        self.bo.x("UPDATE custom_rules SET description=?, expression=?, points=?, floor=?, journeys=?, mode=?, pending=NULL, "
                  "updated_by=?, updated_ms=?, approved_by=?, approved_ms=? WHERE id=?",
                  (definition["description"], definition["expression"], definition["points"], definition["floor"],
                   json.dumps(definition["journeys"]), definition["mode"], actor, now, approved_by,
                   now if approved_by else None, rule_id))
        self._load()

    def approve(self, rule_id, actor):
        row = self.get(rule_id)
        if not row["pending"] or row["retired"]:
            _bad("nothing is waiting for approval on this rule")
        pending = json.loads(row["pending"])
        if pending["requested_by"] == actor:
            raise ValidationFailure(403, "needs_second_person",
                                    "the person who asked for a change cannot approve it; another admin must")
        definition = validate({k: pending[k] for k in FIELDS}, need_name=False)   # the language may have changed since
        self._apply(rule_id, definition, pending["requested_by"], self.bo.now_ms(), approved_by=actor)
        return self.view(self.get(rule_id)), pending

    def reject(self, rule_id, actor):
        row = self.get(rule_id)
        if not row["pending"]:
            _bad("nothing is waiting for approval on this rule")
        self.bo.x("UPDATE custom_rules SET pending=NULL, updated_by=?, updated_ms=? WHERE id=?", (actor, self.bo.now_ms(), rule_id))
        return self.view(self.get(rule_id)), json.loads(row["pending"])

    def retire(self, rule_id, actor, retired=True):
        """Retiring stops a rule at once. Restoring always brings it back in shadow."""
        self.get(rule_id)
        self.bo.x("UPDATE custom_rules SET retired=?, mode='shadow', pending=NULL, updated_by=?, updated_ms=? WHERE id=?",
                  (1 if retired else 0, actor, self.bo.now_ms(), rule_id))
        self._load()
        return self.view(self.get(rule_id))

    # --- deciding ----------------------------------------------------------------------------------------
    def hits(self, facts, journey):
        """(live rules that fired, shadow rules that fired) for one decision's facts."""
        live, shadow = [], []
        for rule in self._active:
            if rule["journeys"] and journey not in rule["journeys"]:
                continue
            if rulelang.evaluate(rule["tree"], facts):
                (live if rule["mode"] == "live" else shadow).append(rule)
        return live, shadow


def apply_rule(score, rule, bands):
    """The score after one rule's points and floor."""
    new = min(config.SCORE_MAX, score + rule["points"])
    if rule["floor"] == "STEP_UP":
        new = max(new, bands["step_up_from"])
    elif rule["floor"] == "BLOCK":
        new = max(new, bands["block_from"])
    return new


def backtest(bo, expression, journeys, points, floor, limit=2000):
    """Run a draft condition over stored decisions. Uses the facts recorded at decision time."""
    from .scoring import level_for

    tree = rulelang.compile_rule(expression)
    rule = {"points": points, "floor": floor}
    labels = {r["session_id"]: r["label"] for r in bo.q("SELECT session_id, label FROM feedback ORDER BY id")}
    rows = bo.q("SELECT record FROM decisions ORDER BY id DESC LIMIT ?", (limit,))
    out = {"decisions": 0, "without_facts": 0, "hits": 0, "by_level": {"ALLOW": 0, "STEP_UP": 0, "BLOCK": 0},
           "would_change": {}, "confirmed_fraud_hits": 0, "confirmed_genuine_hits": 0, "customers": 0, "examples": []}
    customers = set()
    for row in rows:
        rec = json.loads(row["record"])
        facts = rec.get("rule_facts")
        if facts is None:
            out["without_facts"] += 1
            continue
        out["decisions"] += 1
        if journeys and rec.get("event_type") not in journeys:
            continue
        if not rulelang.evaluate(tree, facts):
            continue
        out["hits"] += 1
        out["by_level"][rec["risk_level"]] += 1
        customers.add(rec.get("user_id"))
        would = level_for(apply_rule(rec["risk_score"], rule, config.bands_for(rec.get("event_type"))), rec.get("event_type"))
        if would != rec["risk_level"]:
            key = f"{rec['risk_level']}->{would}"
            out["would_change"][key] = out["would_change"].get(key, 0) + 1
        label = labels.get(rec["session_id"])
        out["confirmed_fraud_hits"] += label == "FRAUD"
        out["confirmed_genuine_hits"] += label == "GENUINE"
        if len(out["examples"]) < 10:
            out["examples"].append({"session_id": rec["session_id"], "user_id": rec.get("user_id"), "time_ms": rec["time_ms"],
                                    "level": rec["risk_level"], "score": rec["risk_score"], "would_level": would})
    out["customers"] = len(customers)
    out["hit_rate"] = round(out["hits"] / out["decisions"], 4) if out["decisions"] else 0.0
    out["note"] = ("Run on the facts recorded with each decision. Decisions made before this feature existed "
                   "carry no facts and are counted under without_facts.")
    return out


def shadow_report(bo, limit=5000):
    """Per rule: how often it fired in shadow or live, and what a shadow rule would have changed."""
    labels = {r["session_id"]: r["label"] for r in bo.q("SELECT session_id, label FROM feedback ORDER BY id")}
    rows = bo.q("SELECT record FROM decisions ORDER BY id DESC LIMIT ?", (limit,))
    report = {}

    def slot(name):
        return report.setdefault(name, {"shadow_hits": 0, "live_hits": 0, "would_change": {}, "confirmed_fraud_hits": 0,
                                        "confirmed_genuine_hits": 0, "last_hit_ms": None})
    for row in rows:
        rec = json.loads(row["record"])
        label = labels.get(rec["session_id"])
        for hit in rec.get("shadow_rules") or []:
            s = slot(hit["rule"])
            s["shadow_hits"] += 1
            s["last_hit_ms"] = max(s["last_hit_ms"] or 0, rec["time_ms"])
            if hit["would_level"] != rec["risk_level"]:
                key = f"{rec['risk_level']}->{hit['would_level']}"
                s["would_change"][key] = s["would_change"].get(key, 0) + 1
            s["confirmed_fraud_hits"] += label == "FRAUD"
            s["confirmed_genuine_hits"] += label == "GENUINE"
        for item in rec.get("score_breakdown") or []:
            if item.get("custom"):
                s = slot(item["reason"][len("CUSTOM_"):].lower())
                s["live_hits"] += 1
                s["last_hit_ms"] = max(s["last_hit_ms"] or 0, rec["time_ms"])
                s["confirmed_fraud_hits"] += label == "FRAUD"
                s["confirmed_genuine_hits"] += label == "GENUINE"
    return {"decisions": len(rows), "rules": report}
