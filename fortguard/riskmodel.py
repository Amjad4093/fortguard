"""Contextual risk model: one model for all customers, trained on outcomes the bank has confirmed.

The rules and the per-customer models ask "does this look like the account holder?". This model asks a
different question: "do payments that look like this one usually turn out to be fraud?". It reads the
context of a decision (amount, new payee, velocity, device and network facts, a few behaviour numbers) and
gives a probability.

- The model is gradient-boosted decision trees with logistic loss, the same family as XGBoost and
  LightGBM, written here in NumPy because the test host cannot install either. It is small (shallow
  trees, a few dozen rounds) on purpose: the training sets it will see first are small.
- Champion and challenger: a newly trained model starts as the challenger. It scores every decision in
  shadow and changes nothing. The champion is the one model whose opinion adds points to the score.
- Governance: every model is a numbered version with its training counts, cross-validated results and
  feature importances kept. Making a challenger the champion needs a second admin. Everything is audited.

Nothing here has seen real fraud. With no confirmed cases there is no model, and the rules decide alone.
"""

import json
import math
import threading

import numpy as np

from . import config
from .schema import ValidationFailure

SCHEMA = """
CREATE TABLE IF NOT EXISTS risk_models (
    id INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT NOT NULL, created_ms INTEGER NOT NULL, created_by TEXT NOT NULL,
    requested_by TEXT, approved_by TEXT, approved_ms INTEGER, retired_ms INTEGER, retired_by TEXT,
    threshold REAL NOT NULL, card TEXT NOT NULL, model TEXT NOT NULL);
"""

SHADOW, CHAMPION, RETIRED = "CHALLENGER", "CHAMPION", "RETIRED"

# name, kind. "log" numbers are stored as log(1 + x). A missing value is MISSING, which trees can split on.
MISSING = -1.0
NUMBERS = ("env.call_seconds", "env.app_install_age_days", "env.background_switches", "session.ip_changes",
           "beh.hesitation", "beh.paste_in_payee", "beh.typing_cpm", "beh.touches", "beh.swipes", "beh.tap_hold_ms",
           "beh.long_presses", "beh.autofills", "profile.match", "profile.sessions",
           "vel.payments_24h", "vel.new_payees_24h", "vel.distinct_payees_7d", "vel.device_customers_7d",
           "vel.payee_customers_7d")
LOGS = ("tx.amount", "vel.amount_24h")
FLAGS = ("tx.is_new_payee", "list.mule_account", "env.rooted", "env.emulator", "env.hooking", "env.debugger",
         "env.remote_control", "env.remote_access_installed", "env.screen_sharing", "env.in_call", "env.vpn",
         "env.mock_location", "env.sim_changed", "env.roaming", "env.developer_options", "env.keyboard_changed",
         "env.unknown_accessibility_service", "env.hotspot", "session.owner_confirmed", "session.location_jump",
         "beh.lying_flat", "beh.walking", "ml.anomalous")
JOURNEYS = ("LOGIN", "ADD_PAYEE", "FUNDS_TRANSFER", "PROFILE_CHANGE")
FEATURES = NUMBERS + LOGS + FLAGS + tuple("journey." + j for j in JOURNEYS) + ("time.hour_sin", "time.hour_cos")

ABOUT = {
    "tx.amount": "Payment amount", "vel.amount_24h": "Amount paid in the last 24 hours", "tx.is_new_payee": "Payee is new",
    "vel.payments_24h": "Payments in the last 24 hours", "vel.new_payees_24h": "New payees in the last 24 hours",
    "vel.distinct_payees_7d": "Different payees in 7 days", "vel.device_customers_7d": "Customers on this phone in 7 days",
    "vel.payee_customers_7d": "Customers who added this payee in 7 days", "profile.match": "Match with the customer's profile",
    "profile.sessions": "Sessions the profile has learned", "beh.hesitation": "Long pauses while entering the payment",
    "beh.typing_cpm": "Typing speed", "beh.touches": "Touches", "beh.swipes": "Swipes", "beh.tap_hold_ms": "Tap hold time",
    "beh.paste_in_payee": "Pastes into the payee field", "beh.long_presses": "Long presses", "beh.autofills": "Autofills",
    "env.in_call": "On a phone call", "env.call_seconds": "Length of the call", "env.remote_control": "Remote-access tool in control",
    "env.vpn": "VPN", "env.rooted": "Rooted phone", "env.emulator": "Emulator", "env.sim_changed": "SIM changed",
    "env.app_install_age_days": "Days since the app was installed", "env.background_switches": "Times sent to the background",
    "session.ip_changes": "IP address changes", "session.location_jump": "Impossible travel", "ml.anomalous": "Per-customer model's doubt",
    "time.hour_sin": "Time of day", "time.hour_cos": "Time of day", "list.mule_account": "Payee on the suspected-mule list",
}


def vector(facts, time_ms):
    """The model's inputs for one decision, from the facts stored with it (scoring.rule_facts)."""
    facts = facts or {}
    row = []
    for name in NUMBERS:
        value = facts.get(name)
        row.append(float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else MISSING)
    for name in LOGS:
        value = facts.get(name)
        row.append(math.log1p(max(0.0, float(value))) if isinstance(value, (int, float)) and not isinstance(value, bool) else MISSING)
    for name in FLAGS:
        value = facts.get(name)
        row.append(MISSING if value is None else float(bool(value)))
    journey = facts.get("journey")
    row.extend(1.0 if journey == j else 0.0 for j in JOURNEYS)
    hour = (time_ms / 3_600_000.0) % 24.0  # UTC: the model only needs it to be consistent
    row.append(math.sin(hour * math.pi / 12.0))
    row.append(math.cos(hour * math.pi / 12.0))
    return row


# --- gradient-boosted trees -----------------------------------------------------------------------------

def _sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.clip(z, -30.0, 30.0)))


def _best_split(X, g, h, rows, cuts):
    """The split of these rows with the largest gain: (gain, feature, cut) or None."""
    G, H = g[rows].sum(), h[rows].sum()
    lam = config.RISK_MODEL_L2
    parent = G * G / (H + lam)
    best = None
    for f, cut in enumerate(cuts):
        if not len(cut):
            continue
        left = X[rows, f][:, None] <= cut[None, :]
        n_left = left.sum(axis=0)
        ok = (n_left >= config.RISK_MODEL_MIN_LEAF) & (len(rows) - n_left >= config.RISK_MODEL_MIN_LEAF)
        if not ok.any():
            continue
        GL, HL = g[rows] @ left, h[rows] @ left
        gain = GL * GL / (HL + lam) + (G - GL) ** 2 / (H - HL + lam) - parent
        gain[~ok] = -np.inf
        i = int(np.argmax(gain))
        if gain[i] > 1e-9 and (best is None or gain[i] > best[0]):
            best = (float(gain[i]), f, float(cut[i]))
    return best


def _grow(X, g, h, rows, cuts, depth, gains):
    split = _best_split(X, g, h, rows, cuts) if depth > 0 and len(rows) >= 2 * config.RISK_MODEL_MIN_LEAF else None
    if split is None:
        return {"v": round(float(-g[rows].sum() / (h[rows].sum() + config.RISK_MODEL_L2) * config.RISK_MODEL_RATE), 6)}
    gain, f, cut = split
    gains[f] += gain
    left = X[rows, f] <= cut
    return {"f": f, "c": cut, "l": _grow(X, g, h, rows[left], cuts, depth - 1, gains),
            "r": _grow(X, g, h, rows[~left], cuts, depth - 1, gains)}


def _tree_values(tree, X):
    if "v" in tree:
        return np.full(len(X), tree["v"])
    left = X[:, tree["f"]] <= tree["c"]
    out = np.empty(len(X))
    out[left] = _tree_values(tree["l"], X[left])
    out[~left] = _tree_values(tree["r"], X[~left])
    return out


def fit(X, y):
    """Train on rows X (n by features) and labels y (1 fraud, 0 genuine). Returns (model, gain per feature)."""
    X, y = np.asarray(X, dtype=float), np.asarray(y, dtype=float)
    cuts = []
    for f in range(X.shape[1]):
        values = np.unique(X[:, f])
        if len(values) > config.RISK_MODEL_BINS:
            values = np.unique(np.quantile(X[:, f], np.linspace(0, 1, config.RISK_MODEL_BINS + 1)))
        cuts.append((values[:-1] + values[1:]) / 2.0 if len(values) > 1 else np.array([]))
    rate = min(max(y.mean(), 1e-4), 1 - 1e-4)
    base = math.log(rate / (1 - rate))
    z = np.full(len(y), base)
    trees, gains, rows = [], np.zeros(X.shape[1]), np.arange(len(y))
    for _ in range(config.RISK_MODEL_ROUNDS):
        p = _sigmoid(z)
        g, h = p - y, np.maximum(p * (1 - p), 1e-6)
        tree = _grow(X, g, h, rows, cuts, config.RISK_MODEL_DEPTH, gains)
        if "v" in tree:  # nothing left to split on
            break
        trees.append(tree)
        z += _tree_values(tree, X)
    return {"base": round(base, 6), "trees": trees, "features": list(FEATURES)}, gains


def predict(model, X):
    X = np.asarray(X, dtype=float)
    z = np.full(len(X), model["base"])
    for tree in model["trees"]:
        z += _tree_values(tree, X)
    return _sigmoid(z)


def predict_one(model, row):
    z = model["base"]
    for tree in model["trees"]:
        while "v" not in tree:
            tree = tree["l"] if row[tree["f"]] <= tree["c"] else tree["r"]
        z += tree["v"]
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


def auc(scores, y):
    """Chance that a fraud scores above a genuine one (0.5 is a coin toss, 1.0 is perfect). None if one class."""
    scores, y = np.asarray(scores, dtype=float), np.asarray(y)
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    if not pos or not neg:
        return None
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores))
    ranks[order] = np.arange(1, len(scores) + 1)
    for value in np.unique(scores):  # ties share the average rank
        tied = scores == value
        if tied.sum() > 1:
            ranks[tied] = ranks[tied].mean()
    return round(float((ranks[y == 1].sum() - pos * (pos + 1) / 2.0) / (pos * neg)), 3)


def _rates(flagged, y):
    flagged, y = np.asarray(flagged, dtype=bool), np.asarray(y)
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    return {"fraud_caught": int((flagged & (y == 1)).sum()), "fraud": pos,
            "genuine_flagged": int((flagged & (y == 0)).sum()), "genuine": neg}


# --- training data --------------------------------------------------------------------------------------

def labelled(bo, limit=None, since_ms=0):
    """Decisions with an outcome, newest first, one per session.

    FRAUD: the bank's feedback said so, or an analyst closed the case as confirmed fraud.
    GENUINE: the feedback said so, or the case was closed as a false positive.
    ASSUMED_GENUINE: allowed, and nobody reported fraud. That is how banks label in practice, and it is
    wrong for any fraud that has not been reported yet.
    """
    limit = limit or config.RISK_MODEL_MAX_ROWS
    truth = {}
    for r in bo.q("SELECT session_id, status FROM cases WHERE status IN ('CONFIRMED_FRAUD','FALSE_POSITIVE')"):
        truth[r["session_id"]] = "FRAUD" if r["status"] == "CONFIRMED_FRAUD" else "GENUINE"
    for r in bo.q("SELECT session_id, label FROM feedback ORDER BY id"):
        truth[r["session_id"]] = r["label"]
    out, seen = [], set()
    for r in bo.q("SELECT session_id, time_ms, risk_level, risk_score, record FROM decisions WHERE time_ms >= ? ORDER BY id DESC LIMIT ?",
                  (since_ms, limit * 3)):
        if r["session_id"] in seen:
            continue
        seen.add(r["session_id"])
        label = truth.get(r["session_id"]) or ("ASSUMED_GENUINE" if r["risk_level"] == "ALLOW" else None)
        if label is None:
            continue
        record = json.loads(r["record"])
        if not record.get("rule_facts"):
            continue
        out.append({"session_id": r["session_id"], "time_ms": r["time_ms"], "label": label, "risk_score": r["risk_score"],
                    "risk_level": r["risk_level"], "facts": record["rule_facts"], "context_model": record.get("context_model")})
        if len(out) >= limit:
            break
    return out


def _counts(rows):
    return {name: sum(1 for r in rows if r["label"] == name) for name in ("FRAUD", "GENUINE", "ASSUMED_GENUINE")}


class RiskModels:
    def __init__(self, bo):
        self.bo = bo
        self._lock = threading.Lock()
        self._cache = None
        self._cache_at = 0.0
        with bo.lock:
            bo.db.executescript(SCHEMA)
            bo.db.commit()

    # --- registry
    def _view(self, row, with_card=True):
        out = {k: row[k] for k in ("id", "status", "created_ms", "created_by", "requested_by", "approved_by", "approved_ms",
                                   "retired_ms", "retired_by", "threshold")}
        out["version"] = "ctx-%d" % row["id"]
        if with_card:
            out["card"] = json.loads(row["card"])
        return out

    def get(self, model_id):
        rows = self.bo.q("SELECT * FROM risk_models WHERE id=?", (model_id,))
        if not rows:
            raise ValidationFailure(404, "not_found", "no such model")
        return rows[0]

    def all(self):
        return [self._view(r) for r in self.bo.q("SELECT * FROM risk_models ORDER BY id DESC")]

    def _changed(self):
        with self._lock:
            self._cache = None

    def active(self):
        """{'champion': (view, model) or None, 'challenger': ...}, re-read at most every few seconds."""
        now = self.bo.clock()
        with self._lock:
            if self._cache is not None and now - self._cache_at < config.RISK_MODEL_CACHE_S:
                return self._cache
        found = {"champion": None, "challenger": None}
        for r in self.bo.q("SELECT * FROM risk_models WHERE status IN (?,?) ORDER BY id DESC", (CHAMPION, SHADOW)):
            slot = "champion" if r["status"] == CHAMPION else "challenger"
            if found[slot] is None:
                found[slot] = (self._view(r, with_card=False), json.loads(r["model"]))
        with self._lock:
            self._cache, self._cache_at = found, now
        return found

    # --- scoring
    def assess(self, facts, time_ms):
        """Both models' opinion of one decision. Only the champion's 'flagged' may change the score."""
        active = self.active()
        if active["champion"] is None and active["challenger"] is None:
            return None
        row = vector(facts, time_ms)
        out = {}
        for slot in ("champion", "challenger"):
            if active[slot] is not None:
                view, model = active[slot]
                p = predict_one(model, row)
                out[slot] = {"version": view["version"], "probability": round(p, 4), "flagged": p >= view["threshold"]}
        return out

    # --- training
    def readiness(self):
        counts = _counts(labelled(self.bo))
        genuine = counts["GENUINE"] + counts["ASSUMED_GENUINE"]
        return {"counts": counts, "need_fraud": config.RISK_MODEL_MIN_FRAUD, "need_genuine": config.RISK_MODEL_MIN_GENUINE,
                "ready": counts["FRAUD"] >= config.RISK_MODEL_MIN_FRAUD and genuine >= config.RISK_MODEL_MIN_GENUINE}

    def train(self, username):
        rows = labelled(self.bo)
        counts = _counts(rows)
        genuine = counts["GENUINE"] + counts["ASSUMED_GENUINE"]
        if counts["FRAUD"] < config.RISK_MODEL_MIN_FRAUD or genuine < config.RISK_MODEL_MIN_GENUINE:
            raise ValidationFailure(409, "not_enough_outcomes",
                                    f"Training needs at least {config.RISK_MODEL_MIN_FRAUD} confirmed frauds and "
                                    f"{config.RISK_MODEL_MIN_GENUINE} genuine decisions. There are {counts['FRAUD']} and {genuine}.")
        X = np.array([vector(r["facts"], r["time_ms"]) for r in rows])
        y = np.array([1 if r["label"] == "FRAUD" else 0 for r in rows])
        rule_score = np.array([r["risk_score"] for r in rows], dtype=float)

        # Results on rows the model did not train on: k folds, each scored by a model built on the others.
        folds = config.RISK_MODEL_FOLDS
        fold_of = np.empty(len(y), dtype=int)
        rng = np.random.default_rng(len(y))  # the same data gives the same folds
        for cls in (0, 1):
            idx = rng.permutation(np.flatnonzero(y == cls))
            fold_of[idx] = np.arange(len(idx)) % folds
        held_out = np.empty(len(y))
        for k in range(folds):
            part, _ = fit(X[fold_of != k], y[fold_of != k])
            held_out[fold_of == k] = predict(part, X[fold_of == k])

        # Flag above the score that only about 1 genuine decision in 100 reaches, and never below 0.5.
        threshold = max(0.5, float(np.quantile(held_out[y == 0], 1 - config.RISK_MODEL_TARGET_FPR)))
        threshold = round(min(threshold, 0.99), 4)
        model, gains = fit(X, y)
        total = gains.sum() or 1.0
        top = sorted(((FEATURES[i], float(gains[i] / total)) for i in range(len(FEATURES)) if gains[i] > 0), key=lambda t: -t[1])
        stepup = config.bands_for("FUNDS_TRANSFER")["step_up_from"]
        card = {
            "algorithm": f"Gradient-boosted decision trees, logistic loss: {len(model['trees'])} trees of depth {config.RISK_MODEL_DEPTH}",
            "trained_on": counts, "rows": len(rows),
            "first_ms": min(r["time_ms"] for r in rows), "last_ms": max(r["time_ms"] for r in rows),
            "inputs": len(FEATURES),
            "validation": {
                "method": f"{folds}-fold cross-validation: every row is scored by a model that did not train on it",
                "auc": auc(held_out, y), "rules_auc": auc(rule_score, y),
                "at_threshold": _rates(held_out >= threshold, y),
                "rules_at_step_up": _rates(rule_score >= stepup, y),
            },
            "top_inputs": [{"name": n, "about": ABOUT.get(n, n), "share": round(s, 3)} for n, s in top[:8] if s >= 0.005],
            "limits": ["Trained only on the decisions and outcomes stored on this server.",
                       "Allowed decisions with no fraud report are counted as genuine; unreported fraud is mislabelled.",
                       "The rule score was used to decide which sessions were reviewed, so the comparison with the rules favours the rules.",
                       "Results on a few dozen frauds move a lot from one training to the next."],
        }
        now = self.bo.now_ms()
        # One challenger at a time: a new one replaces the old one.
        self.bo.x("UPDATE risk_models SET status=?, retired_ms=?, retired_by=?, requested_by=NULL WHERE status=?", (RETIRED, now, username, SHADOW))
        cur = self.bo.x("INSERT INTO risk_models (status, created_ms, created_by, threshold, card, model) VALUES (?,?,?,?,?,?)",
                        (SHADOW, now, username, threshold, json.dumps(card), json.dumps(model)))
        self._changed()
        return self._view(self.get(cur.lastrowid))

    # --- promotion: asked for by one admin, approved by another
    def request(self, model_id, username):
        row = self.get(model_id)
        if row["status"] == CHAMPION:
            raise ValidationFailure(409, "already_champion", "this model is already the champion")
        self.bo.x("UPDATE risk_models SET requested_by=? WHERE id=?", (username, model_id))
        return self._view(self.get(model_id))

    def approve(self, model_id, username):
        row = self.get(model_id)
        if not row["requested_by"]:
            raise ValidationFailure(409, "nothing_pending", "nobody has asked to make this model the champion")
        if username in (row["requested_by"], row["created_by"]):
            raise ValidationFailure(403, "needs_second_person", "a different admin from the one who trained or requested it must approve")
        now = self.bo.now_ms()
        self.bo.x("UPDATE risk_models SET status=?, retired_ms=?, retired_by=? WHERE status=?", (RETIRED, now, username, CHAMPION))
        self.bo.x("UPDATE risk_models SET status=?, approved_by=?, approved_ms=?, requested_by=NULL, retired_ms=NULL, retired_by=NULL WHERE id=?",
                  (CHAMPION, username, now, model_id))
        self._changed()
        return self._view(self.get(model_id))

    def reject(self, model_id, username):
        row = self.get(model_id)
        if not row["requested_by"]:
            raise ValidationFailure(409, "nothing_pending", "nobody has asked to make this model the champion")
        self.bo.x("UPDATE risk_models SET requested_by=? WHERE id=?", (None, model_id))
        return self._view(self.get(model_id))

    def retire(self, model_id, username):
        """Take a model out of use at once. One admin is enough: removing a model is the safe direction."""
        self.get(model_id)
        self.bo.x("UPDATE risk_models SET status=?, retired_ms=?, retired_by=?, requested_by=NULL WHERE id=?",
                  (RETIRED, self.bo.now_ms(), username, model_id))
        self._changed()
        return self._view(self.get(model_id))

    # --- champion against challenger on decisions made after both were in place
    def comparison(self):
        """How the rules, the champion and the challenger did on decisions each of them scored live."""
        active = self.active()
        versions = {slot: active[slot][0] for slot in ("champion", "challenger") if active[slot]}
        if not versions:
            return None
        since = min(v["created_ms"] for v in versions.values())
        rows = labelled(self.bo, since_ms=since)
        out = {"since_ms": since, "decisions": len(rows), "counts": _counts(rows), "models": {}}
        y = np.array([1 if r["label"] == "FRAUD" else 0 for r in rows])
        for slot, view in versions.items():
            scored = [(i, (r["context_model"] or {}).get(slot)) for i, r in enumerate(rows)]
            scored = [(i, s) for i, s in scored if s and s.get("version") == view["version"]]
            idx = np.array([i for i, _ in scored], dtype=int)
            if not len(idx):
                out["models"][slot] = {"version": view["version"], "scored": 0}
                continue
            p = np.array([s["probability"] for _, s in scored])
            flagged = np.array([bool(s["flagged"]) for _, s in scored])
            rules = np.array([rows[i]["risk_score"] for i in idx], dtype=float)
            out["models"][slot] = {"version": view["version"], "scored": int(len(idx)), "auc": auc(p, y[idx]),
                                   "rules_auc": auc(rules, y[idx]), **_rates(flagged, y[idx])}
        return out
