"""Per-customer anomaly model: an unsupervised machine-learning check on how a session was typed.

What it is
    A multivariate Gaussian novelty detector. For each customer it learns, from that customer's own
    allowed sessions, the usual value of each behavioral feature AND how the features move together
    (their covariance). A new session is scored by its Mahalanobis distance from that learned shape.
    Typing a little slower with a slightly longer key hold is normal for a person; typing slower with
    a shorter hold and a different touch pressure may not be, even when each value alone looks fine.

Why this model
    A customer has 10 to 30 learned sessions, so the model must work with very little data. On
    simulated customers a covariance model beat k-nearest-neighbour and Isolation Forest at that size,
    and plain Isolation Forest was clearly worse (see docs/ML.md and tests/test_mlmodel.py).
    Covariance is shrunk toward the identity matrix so it stays stable with few sessions.

How the threshold is set
    There is no fixed cut-off. Each customer's threshold comes from their own data: every learned
    session is scored by a model fitted on the others (leave-one-out), and a new session is flagged
    only when it is further out than ML_MARGIN times the furthest of those. A customer whose behavior
    varies a lot gets a wider threshold automatically.

What it is not
    It is not trained on fraud. No labeled fraud data exists yet, so nothing here measures how much
    real fraud it catches. It answers one question: "is this session unlike this customer's own past
    sessions?". Its weight in the score is set in config.WEIGHTS and should be tuned on pilot data.
"""

import math

import numpy as np

from . import config

MODEL_NAME = "covariance-novelty-1"

# The seven baseline features plus eight more that the server already computes for every session.
FEATURES = (
    "ft_swipe_curvature_mean_px",
    "ft_keystroke_hold_time_avg",
    "ft_keystroke_flight_time_avg",
    "ft_keystroke_flight_time_std",
    "ft_accel_variance",
    "ft_tremor_band_ratio",
    "ft_device_angle_stability",
    "ft_touch_pressure_mean",
    "ft_touch_pressure_std",
    "ft_touch_size_mean",
    "ft_swipe_speed_px_s",
    "ft_tap_interval_mean_ms",
    "ft_typing_speed_cpm",
    "ft_correction_rate",
    "ft_gyro_variance",
)
# Variance-like features are compared on a log scale, where human variation is closer to normal.
LOG_FEATURES = {"ft_accel_variance", "ft_device_angle_stability", "ft_gyro_variance"}


def vector(feats):
    """The model's view of a session: finite numbers only, variance-like features on a log scale."""
    out = {}
    for name in FEATURES:
        v = feats.get(name) if feats else None
        if v is None or isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
            continue
        out[name] = math.log10(max(v, 1e-9)) if name in LOG_FEATURES else float(v)
    return out


def _fit(data):
    """Mean, spread and inverse covariance of the rows of `data` (sessions by features)."""
    n, d = data.shape
    mean = data.mean(axis=0)
    # A feature a phone reports as constant would otherwise make any change look infinite.
    spread = np.maximum(data.std(axis=0), np.maximum(np.abs(mean) * config.ML_REL_SD_FLOOR, 1e-3))
    z = (data - mean) / spread
    cov = np.cov(z, rowvar=False) if n > 1 else np.eye(d)
    cov = np.atleast_2d(cov)
    shrink = min(config.ML_SHRINK_MAX, max(config.ML_SHRINK_MIN, d / (d + n)))
    cov = (1.0 - shrink) * cov + shrink * np.eye(d)
    return mean, spread, np.linalg.inv(cov)


def _distance(fit, x):
    mean, spread, inv = fit
    z = (x - mean) / spread
    return float(math.sqrt(max(0.0, z @ inv @ z))), z, inv


class AnomalyModel:
    """One customer's model. Build it with AnomalyModel.train(rows); it is None-safe through assess()."""

    def __init__(self, names, data):
        self.names = names            # feature names, in column order
        self.data = data              # learned sessions by features
        self._subsets = {}            # tuple of column indexes -> (fit, leave-one-out distances)

    @property
    def sessions(self):
        return int(self.data.shape[0])

    @classmethod
    def train(cls, rows):
        """`rows` are stored session vectors (dicts). Returns None when there is too little to learn from."""
        if len(rows) < config.ML_MIN_SESSIONS:
            return None
        # Use the features this customer's sessions usually have, then the sessions that have them all.
        common = [n for n in FEATURES if sum(1 for r in rows if n in r) >= config.ML_FEATURE_PRESENT * len(rows)]
        full = [r for r in rows if all(n in r for n in common)]
        if len(common) < config.ML_MIN_FEATURES or len(full) < config.ML_MIN_SESSIONS:
            return None
        return cls(tuple(common), np.array([[r[n] for n in common] for r in full], dtype=float))

    def _subset(self, cols):
        cached = self._subsets.get(cols)
        if cached is None:
            data = self.data[:, list(cols)]
            fit = _fit(data)
            n = data.shape[0]
            # Leave-one-out: how far each learned session sits from a model that never saw it.
            loo = [
                _distance(_fit(np.delete(data, i, axis=0)), data[i])[0]
                for i in range(n)
            ]
            cached = (fit, sorted(loo))
            if len(self._subsets) > 32:
                self._subsets.clear()
            self._subsets[cols] = cached
        return cached

    def score(self, vec):
        """Score one session vector (a dict from vector()). Returns the `ml` block for the response."""
        cols = tuple(i for i, name in enumerate(self.names) if name in vec)
        if len(cols) < config.ML_MIN_FEATURES:
            return _block("INSUFFICIENT_FEATURES", self.sessions, features=len(cols))
        fit, loo = self._subset(cols)
        x = np.array([vec[self.names[i]] for i in cols], dtype=float)
        dist, z, inv = _distance(fit, x)
        threshold = config.ML_MARGIN * loo[-1]
        # Each feature's share of the squared distance, so the portal can say what looked unusual.
        share = z * (inv @ z)
        order = np.argsort(-share)
        top = [self.names[cols[i]] for i in order[:3] if share[i] > 0]
        further = sum(1 for v in loo if v >= dist)
        return _block(
            "ACTIVE", self.sessions, features=len(cols),
            distance=round(dist, 3), threshold=round(threshold, 3),
            anomaly_score=round(min(1.0, dist / (2.0 * threshold)), 2) if threshold > 0 else None,
            p_value=round((1 + further) / (len(loo) + 1), 3),
            anomalous=bool(dist > threshold), top_features=top,
        )


def _block(status, sessions, features=0, distance=None, threshold=None, anomaly_score=None,
           p_value=None, anomalous=False, top_features=()):
    return {
        "model": MODEL_NAME, "status": status, "sessions": sessions, "required": config.ML_MIN_SESSIONS,
        "features": features, "distance": distance, "threshold": threshold,
        "anomaly_score": anomaly_score, "p_value": p_value, "anomalous": anomalous,
        "top_features": list(top_features),
    }


def assess(model, feats, learned_sessions=0):
    """The `ml` block for a session. `model` may be None while the customer is still being learned."""
    if model is None:
        return _block("LEARNING" if learned_sessions else "NONE", learned_sessions)
    return model.score(vector(feats))


EMPTY = _block("NONE", 0)
