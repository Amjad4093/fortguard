"""The per-customer machine-learning anomaly model (fortguard/mlmodel.py).

The detection-rate tests use simulated people: each has their own typical values, and their sessions
vary around those with realistic links between features (a rushed session is faster on several timing
features at once). They prove the model works as designed. They are not evidence of how much real
fraud it catches.
"""

import numpy as np
import pytest

from fortguard import config, mlmodel
from fortguard.client import run_session

NAMES = mlmodel.FEATURES
#          curv hold flight fstd  accel trem  angle press pstd size  speed tap   cpm   corr  gyro
POP_MU = np.array([18, 95, 190, 57, -2.3, .30, -1.5, .55, .12, .35, 900, 800, 200, .08, -3.8])
POP_SD = np.array([6, 15, 45, 14, .4, .10, .4, .12, .04, .08, 300, 250, 60, .04, .4])
DAY_SD = np.array([3, 8, 20, 8, .15, .04, .15, .04, .02, .03, 120, 120, 25, .03, .15])
PACE = np.array([0, .6, .8, .6, 0, 0, 0, 0, 0, 0, .3, .5, -.8, .2, 0])     # a rushed or tired session
MOVE = np.array([0, 0, 0, 0, .8, .5, .7, .3, .2, 0, 0, 0, 0, 0, .8])        # walking versus sitting


def person(rng):
    return POP_MU + POP_SD * rng.standard_normal(len(NAMES))


def sessions(rng, mu, n):
    pace, move = rng.standard_normal((n, 1)), rng.standard_normal((n, 1))
    own = np.sqrt(1 - PACE ** 2 - MOVE ** 2) * rng.standard_normal((n, len(NAMES)))
    data = mu + DAY_SD * (pace * PACE + move * MOVE + own)
    return [dict(zip(NAMES, row)) for row in data.tolist()]


def flagged(model, rows):
    """Share of `rows` (already in model space) the model flags."""
    hits = 0
    for row in rows:
        cols = tuple(range(len(model.names)))
        fit, loo = model._subset(cols)
        dist = mlmodel._distance(fit, np.array([row[n] for n in model.names]))[0]
        hits += dist > config.ML_MARGIN * loo[-1]
    return hits / len(rows)


def rates(n_learned, users=60, seed=5):
    rng = np.random.default_rng(seed)
    own, close, other = [], [], []
    for _ in range(users):
        mu = person(rng)
        model = mlmodel.AnomalyModel.train(sessions(rng, mu, n_learned))
        own.append(flagged(model, sessions(rng, mu, 20)))
        near = mu + DAY_SD * 1.5 * rng.choice([-1, 1], len(NAMES))  # habits close to the customer's
        close.append(flagged(model, sessions(rng, near, 20)))
        other.append(flagged(model, [sessions(rng, person(rng), 1)[0] for _ in range(20)]))
    return float(np.mean(own)), float(np.mean(close)), float(np.mean(other))


@pytest.mark.parametrize("n_learned", [10, 20, 30])
def test_simulated_customers_are_left_alone_and_other_people_are_caught(n_learned):
    false_alarms, similar_person, different_person = rates(n_learned)
    assert false_alarms < 0.05, "the customer's own sessions must rarely be flagged"
    assert different_person > 0.95, "a session by a different person should almost always be flagged"
    assert similar_person > 0.5, "a person with similar habits should be flagged more often than not"


def test_more_learned_sessions_mean_fewer_false_alarms():
    assert rates(30)[0] <= rates(10)[0]


def test_no_model_before_enough_sessions():
    rng = np.random.default_rng(1)
    rows = sessions(rng, person(rng), config.ML_MIN_SESSIONS - 1)
    assert mlmodel.AnomalyModel.train(rows) is None
    assert mlmodel.assess(None, {}, learned_sessions=3)["status"] == "LEARNING"
    assert mlmodel.assess(None, {}, learned_sessions=0)["status"] == "NONE"


def test_a_session_missing_some_features_is_still_scored():
    rng = np.random.default_rng(2)
    mu = person(rng)
    model = mlmodel.AnomalyModel.train(sessions(rng, mu, 20))
    row = sessions(rng, mu, 1)[0]
    for name in NAMES[:3]:
        del row[name]
    out = model.score(row)
    assert out["status"] == "ACTIVE" and out["features"] == len(NAMES) - 3 and out["anomalous"] is False


def test_too_few_features_gives_no_opinion():
    rng = np.random.default_rng(3)
    mu = person(rng)
    model = mlmodel.AnomalyModel.train(sessions(rng, mu, 20))
    row = {NAMES[0]: 18.0, NAMES[1]: 95.0}
    out = model.score(row)
    assert out["status"] == "INSUFFICIENT_FEATURES" and out["anomalous"] is False


def test_a_feature_the_phone_reports_as_constant_does_not_break_the_model():
    rng = np.random.default_rng(4)
    mu = person(rng)
    rows = sessions(rng, mu, 15)
    for r in rows:
        r["ft_touch_pressure_mean"] = 1.0   # many phones report a fixed pressure
        r["ft_touch_pressure_std"] = 0.0
    model = mlmodel.AnomalyModel.train(rows)
    probe = sessions(rng, mu, 1)[0]
    probe["ft_touch_pressure_mean"], probe["ft_touch_pressure_std"] = 1.0, 0.0
    out = model.score(probe)
    assert out["status"] == "ACTIVE" and np.isfinite(out["distance"]) and out["anomalous"] is False


def test_the_feature_that_moved_is_named():
    rng = np.random.default_rng(6)
    mu = person(rng)
    model = mlmodel.AnomalyModel.train(sessions(rng, mu, 25))
    row = dict(zip(NAMES, mu.tolist()))
    row["ft_keystroke_hold_time_avg"] += 12 * DAY_SD[1]
    out = model.score(row)
    assert out["anomalous"] is True and out["top_features"][0] == "ft_keystroke_hold_time_avg"


def test_vector_drops_missing_and_non_numeric_values_and_logs_variances():
    v = mlmodel.vector({"ft_accel_variance": 0.01, "ft_typing_speed_cpm": None, "ft_correction_rate": True,
                        "ft_touch_size_mean": float("nan"), "ft_keystroke_hold_time_avg": 90})
    assert v == {"ft_accel_variance": pytest.approx(-2.0), "ft_keystroke_hold_time_avg": 90.0}


# --- through the API -------------------------------------------------------------------------------

def go(api, make_session, scenario, seed, user="usr_mlmodel1"):
    s = make_session(scenario, seed)
    s["evaluate"]["user_id"] = user
    s["evaluate"].pop("request_id", None)
    return run_session(api, s)[1]


def mature(api, make_session, user="usr_mlmodel1", count=None):
    for i in range(count or config.ML_MIN_SESSIONS):
        go(api, make_session, "genuine", 300 + i, user)


def test_model_is_learning_then_active(api, make_session):
    first = go(api, make_session, "genuine", 1)
    assert first["ml"]["status"] == "NONE" and first["scoring_mode"] == "RULES_ONLY"
    second = go(api, make_session, "genuine", 2)
    assert second["ml"]["status"] == "LEARNING" and second["ml"]["sessions"] == 1
    mature(api, make_session)
    later = go(api, make_session, "genuine", 50)
    assert later["ml"]["status"] == "ACTIVE" and later["scoring_mode"] == "RULES_AND_ML"
    assert later["ml"]["model"] == mlmodel.MODEL_NAME and later["ml"]["features"] >= config.ML_MIN_FEATURES


def test_scripted_input_is_flagged_by_the_model_and_scored(api, make_session):
    mature(api, make_session)
    b = go(api, make_session, "bot_scripted", 7)
    assert b["ml"]["anomalous"] is True and "REASON_ML_BEHAVIOR_ANOMALY" in b["reason_codes"]
    assert {"reason": "REASON_ML_BEHAVIOR_ANOMALY", "points": 300} in b["score_breakdown"]
    assert b["ml"]["top_features"], "the model must say what looked unusual"


def test_the_customers_own_sessions_are_rarely_flagged(api, make_session, clock):
    mature(api, make_session, count=15)
    clock.now += 120  # a new minute, so the enrolment rate limit does not refuse the test's devices
    results = [go(api, make_session, "genuine", 400 + i) for i in range(25)]
    flagged_own = sum(r["ml"]["anomalous"] for r in results)
    assert flagged_own <= 2, f"{flagged_own} of 25 genuine sessions were flagged"
    # A lone model flag on a payment asks for a fingerprint or face check; it never blocks the customer.
    assert all(r["risk_level"] != "BLOCK" for r in results), "a lone model flag must not block a customer"
    assert all(r["risk_level"] == ("STEP_UP" if r["ml"]["anomalous"] else "ALLOW") for r in results)


def test_a_session_reported_as_fraud_is_removed_from_the_model(api, app, make_session):
    mature(api, make_session)
    assert app.fortguard_baselines.profile("usr_mlmodel1")["ml"] is not None
    victim = make_session("genuine", 300)
    app.fortguard_baselines.forget(victim["session_id"])
    assert app.fortguard_baselines.profile("usr_mlmodel1")["ml"] is None, "back under the minimum"


def test_the_decision_record_and_customer_page_show_the_model(clock, make_session):
    from fortguard.app import create_app
    from fortguard.client import InProcessTransport
    app = create_app(clock=clock, admin_password="admin-test-password", dev_mode=True)
    api = InProcessTransport(app)
    mature(api, make_session)
    go(api, make_session, "genuine", 60)
    c = app.test_client()
    token = c.post("/v1/auth/login", json={"username": "admin", "password": "admin-test-password"}).get_json()["token"]
    r = c.get("/v1/bo/customers/usr_mlmodel1", headers={"Authorization": f"Bearer {token}"})
    body = r.get_json()
    assert r.status_code == 200
    assert body["ml_model"]["status"] == "ACTIVE" and body["ml_model"]["features"]
    assert body["latest"]["ml"]["status"] == "ACTIVE" and body["latest"]["scoring_mode"] == "RULES_AND_ML"
    listed = c.get("/v1/bo/customers", headers={"Authorization": f"Bearer {token}"}).get_json()["customers"]
    assert [x["ml"] for x in listed if x["user_id"] == "usr_mlmodel1"] == ["ACTIVE"]
