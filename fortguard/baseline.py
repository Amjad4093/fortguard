"""Per-user behavioral baselines and the biometric match score (first version: statistical).

How it works
    * After each ALLOW decision, the session's behavioral features are stored against the user.
      Only allowed sessions are learned from, and a session later reported as fraud is removed,
      so an attacker cannot teach the baseline.
    * A user's profile is the mean and spread of each feature over their last 30 learned sessions.
    * The match score compares a new session with that profile: 1.0 is typical for this user, 0.0 is
      far outside their normal range. Each feature scores 1 - z/4 (floored at 0), where z is how many
      standard deviations it sits from the user's mean; the match is the average over features present.
    * Cold start: with fewer than BASELINE_MIN_SESSIONS learned sessions the baseline is "LEARNING"
      and the match score cannot change the decision (PRD section 6).

This is a transparent statistical model, not a trained neural network. It is a sound first version
and a benchmark for the learned model (backlog E3-03) once real, consented pilot data exists.
"""

import json
import math
import statistics
import threading

from . import config

PROFILE_FEATURES = (
    "ft_swipe_curvature_mean_px",
    "ft_keystroke_hold_time_avg",
    "ft_keystroke_flight_time_avg",
    "ft_keystroke_flight_time_std",
    "ft_accel_variance",
    "ft_tremor_band_ratio",
    "ft_device_angle_stability",
)
# Variance-like features are compared on a log scale, where human variation is closer to normal.
LOG_FEATURES = {"ft_accel_variance", "ft_device_angle_stability"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline_sessions (
    user_id TEXT NOT NULL, session_id TEXT NOT NULL, time_ms INTEGER NOT NULL, features TEXT NOT NULL,
    PRIMARY KEY (user_id, session_id));
CREATE INDEX IF NOT EXISTS baseline_user_time ON baseline_sessions(user_id, time_ms);
"""


def _vector(feats):
    out = {}
    for name in PROFILE_FEATURES:
        v = feats.get(name) if feats else None
        if v is None or isinstance(v, bool) or not math.isfinite(v):
            continue
        out[name] = math.log10(max(v, 1e-9)) if name in LOG_FEATURES else float(v)
    return out


class Baselines:
    def __init__(self, bo):
        self.bo = bo
        self._cache = {}          # user_id -> profile; invalidated on every change for that user
        self._cache_lock = threading.Lock()
        with bo.lock:
            bo.db.executescript(SCHEMA)
            bo.db.commit()

    def _rows(self, user_id):
        return self.bo.q(
            "SELECT features FROM baseline_sessions WHERE user_id=? ORDER BY time_ms DESC LIMIT ?",
            (user_id, config.BASELINE_WINDOW))

    def profile(self, user_id):
        with self._cache_lock:
            cached = self._cache.get(user_id)
        if cached is not None:
            return cached
        prof = self._profile(user_id)
        with self._cache_lock:
            if len(self._cache) > 100_000:
                self._cache.clear()
            self._cache[user_id] = prof
        return prof

    def _invalidate(self, user_id=None):
        with self._cache_lock:
            if user_id is None:
                self._cache.clear()
            else:
                self._cache.pop(user_id, None)

    def _profile(self, user_id):
        rows = [json.loads(r["features"]) for r in self._rows(user_id)]
        stats = {}
        for name in PROFILE_FEATURES:
            values = [r[name] for r in rows if name in r]
            if len(values) >= 2:
                stats[name] = (statistics.fmean(values), statistics.pstdev(values))
        return {"sessions": len(rows), "stats": stats}

    def assess(self, user_id, feats):
        """Return the baseline block for the response, and whether the anomaly rule fires."""
        prof = self.profile(user_id)
        n = prof["sessions"]
        status = "MATURE" if n >= config.BASELINE_MIN_SESSIONS else ("LEARNING" if n else "NONE")
        vec = _vector(feats)
        parts = {}
        for name, x in vec.items():
            if name not in prof["stats"]:
                continue
            mean, sd = prof["stats"][name]
            floor = max(abs(mean) * config.BASELINE_REL_SD_FLOOR, 1e-3)
            z = abs(x - mean) / max(sd, floor)
            parts[name] = max(0.0, 1.0 - z / 4.0)
        match = round(statistics.fmean(parts.values()), 2) if len(parts) >= config.BASELINE_MIN_FEATURES else None
        anomalous = status == "MATURE" and match is not None and match < config.BASELINE_ANOMALY_BELOW
        least_typical = sorted(parts, key=parts.get)[:3] if parts else []
        return {
            "status": status, "sessions": n, "required": config.BASELINE_MIN_SESSIONS,
            "match_score": match if status == "MATURE" else None,
            "match_score_preview": match,  # computed during LEARNING too, but never acted on
            "least_typical_features": least_typical,
        }, anomalous

    def learn(self, user_id, session_id, feats, time_ms):
        vec = _vector(feats)
        if len(vec) < config.BASELINE_MIN_FEATURES:
            return False
        self.bo.x("INSERT OR REPLACE INTO baseline_sessions VALUES (?,?,?,?)", (user_id, session_id, time_ms, json.dumps(vec)))
        # keep the table small: only the most recent window per user matters
        self.bo.x(
            "DELETE FROM baseline_sessions WHERE user_id=? AND session_id NOT IN "
            "(SELECT session_id FROM baseline_sessions WHERE user_id=? ORDER BY time_ms DESC LIMIT ?)",
            (user_id, user_id, config.BASELINE_WINDOW))
        self._invalidate(user_id)
        return True

    def forget(self, session_id):
        """Remove a session from every baseline, for example after it is reported as fraud."""
        n = self.bo.x("DELETE FROM baseline_sessions WHERE session_id=?", (session_id,)).rowcount
        self._invalidate()
        return n

    def forget_user(self, user_id):
        n = self.bo.x("DELETE FROM baseline_sessions WHERE user_id=?", (user_id,)).rowcount
        self._invalidate(user_id)
        return n
