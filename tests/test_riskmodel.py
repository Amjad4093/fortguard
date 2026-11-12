"""The contextual risk model: the trees, training from confirmed outcomes, champion and challenger, approval."""

import numpy as np
import pytest

from fortguard import config, riskmodel
from fortguard.app import create_app
from fortguard.client import InProcessTransport, run_session
from fortguard.generator import build_session

ADMIN_PW = "admin-test-password"
FRAUD = ("remote_control", "coached_scam", "emulator_bot", "bot_scripted")
GENUINE = ("genuine", "genuine_new_payee")


class Portal:
    def __init__(self, app):
        self.c, self.token = app.test_client(), None

    def call(self, method, path, json=None):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        r = getattr(self.c, method)(path, json=json, headers=headers)
        return r.status_code, r.get_json(silent=True)

    def login(self, username, password):
        status, body = self.call("post", "/v1/auth/login", {"username": username, "password": password})
        self.token = body["token"]
        return self


@pytest.fixture
def bo_app(clock, monkeypatch):
    monkeypatch.setenv("FORTGUARD_RATE_LIMITS_OFF", "1")
    return create_app(clock=clock, admin_password=ADMIN_PW, dev_mode=True)


@pytest.fixture
def admin(bo_app):
    return Portal(bo_app).login("admin", ADMIN_PW)


def second_admin(bo_app, admin):
    assert admin.call("post", "/v1/bo/users", {"username": "second.admin", "password": "long-enough-pw", "role": "admin"})[0] == 201
    return Portal(bo_app).login("second.admin", "long-enough-pw")


def play(bo_app, clock, name, seed, label=None):
    api = InProcessTransport(bo_app)
    clock.now += 7
    session = build_session(name, int(clock() * 1000), seed)
    status, body = run_session(api, session, now_ms=int(clock() * 1000))
    assert status == 200
    if label:
        assert api.post("/v1/feedback", {"session_id": body["session_id"], "label": label}, auth=True)[0] == 201
    return body


def history(bo_app, clock, frauds=24, genuine=60):
    # Mixed in time: all the frauds first would teach the model the time of day, not the fraud.
    for i in range(max(frauds, genuine)):
        if i * frauds // genuine != (i + 1) * frauds // genuine:
            n = i * frauds // genuine
            play(bo_app, clock, FRAUD[n % len(FRAUD)], 1000 + n, "FRAUD")
        if i < genuine:
            play(bo_app, clock, GENUINE[i % len(GENUINE)], 5000 + i)


# --- the trees ---------------------------------------------------------------------------------------------

def toy(n, seed):
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(n, 6))
    X[:, 3] = rng.integers(0, 2, n)
    y = ((X[:, 0] > 0.3) & (X[:, 3] == 1) | (X[:, 1] < -1.2)).astype(int)  # an interaction no single input gives
    return X, y


def test_trees_learn_an_interaction_and_hold_up_on_new_rows():
    X, y = toy(1200, 1)
    model, gains = riskmodel.fit(X, y)
    Xt, yt = toy(600, 2)
    assert riskmodel.auc(riskmodel.predict(model, Xt), yt) > 0.97
    assert set(np.argsort(gains)[-3:]) == {0, 1, 3}
    assert gains[5] < 0.02 * gains.sum()


def test_one_row_and_many_rows_agree():
    X, y = toy(400, 3)
    model, _ = riskmodel.fit(X, y)
    many = riskmodel.predict(model, X[:25])
    assert [riskmodel.predict_one(model, list(r)) for r in X[:25]] == pytest.approx(list(many))


def test_auc():
    assert riskmodel.auc([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1]) == 1.0
    assert riskmodel.auc([0.9, 0.8, 0.2, 0.1], [0, 0, 1, 1]) == 0.0
    assert riskmodel.auc([0.5, 0.5, 0.5, 0.5], [0, 1, 0, 1]) == 0.5
    assert riskmodel.auc([0.1, 0.2], [0, 0]) is None


def test_vector_marks_missing_values_and_has_one_number_per_input():
    row = riskmodel.vector({"journey": "FUNDS_TRANSFER", "tx.amount": 99.0, "env.vpn": True}, 0)
    assert len(row) == len(riskmodel.FEATURES)
    at = riskmodel.FEATURES.index
    assert row[at("tx.amount")] == pytest.approx(np.log(100.0)) and row[at("env.vpn")] == 1.0
    assert row[at("env.rooted")] == riskmodel.MISSING and row[at("journey.FUNDS_TRANSFER")] == 1.0


# --- training and the registry ---------------------------------------------------------------------------------

def test_no_model_without_enough_confirmed_outcomes(bo_app, admin, clock):
    play(bo_app, clock, "genuine", 1)
    play(bo_app, clock, "coached_scam", 2, "FRAUD")
    status, body = admin.call("post", "/v1/bo/models/train")
    assert status == 409 and body["error"]["code"] == "not_enough_outcomes"
    _, page = admin.call("get", "/v1/bo/models")
    assert page["models"] == [] and page["readiness"]["ready"] is False
    assert page["readiness"]["counts"] == {"FRAUD": 1, "GENUINE": 0, "ASSUMED_GENUINE": 1}
    assert play(bo_app, clock, "genuine", 3)["context_model"] is None


def test_challenger_scores_in_shadow_and_changes_nothing(bo_app, admin, clock):
    history(bo_app, clock)
    before = play(bo_app, clock, "coached_scam", 77)
    status, page = admin.call("post", "/v1/bo/models/train")
    assert status == 201
    model = page["models"][0]
    card = model["card"]
    assert model["status"] == "CHALLENGER" and model["version"] == "ctx-1"
    assert card["trained_on"]["FRAUD"] == 24 and card["validation"]["auc"] > 0.9 and card["top_inputs"]
    clock.now += 10  # past the cache
    after = play(bo_app, clock, "coached_scam", 79)
    assert after["risk_score"] == before["risk_score"] and after["score_breakdown"] == before["score_breakdown"]
    assert "REASON_CONTEXT_MODEL_HIGH_RISK" not in after["reason_codes"]
    assert set(after["context_model"]) == {"challenger"} and after["context_model"]["challenger"]["probability"] > 0.5
    assert play(bo_app, clock, "genuine", 78)["context_model"]["challenger"]["flagged"] is False


def test_promotion_needs_a_second_admin_and_then_the_champion_adds_points(bo_app, admin, clock):
    history(bo_app, clock)
    _, page = admin.call("post", "/v1/bo/models/train")
    mid = page["models"][0]["id"]
    assert admin.call("post", f"/v1/bo/models/{mid}/approve")[0] == 409  # nobody asked yet
    assert admin.call("post", f"/v1/bo/models/{mid}/request")[0] == 200
    status, body = admin.call("post", f"/v1/bo/models/{mid}/approve")
    assert status == 403 and body["error"]["code"] == "needs_second_person"
    second = second_admin(bo_app, admin)
    status, page = second.call("post", f"/v1/bo/models/{mid}/approve")
    assert status == 200 and page["models"][0]["status"] == "CHAMPION" and page["models"][0]["approved_by"] == "second.admin"

    clock.now += 10
    scam = play(bo_app, clock, "coached_scam", 91)
    assert {"reason": "REASON_CONTEXT_MODEL_HIGH_RISK", "points": config.WEIGHTS["REASON_CONTEXT_MODEL_HIGH_RISK"]} in scam["score_breakdown"] \
        or scam["risk_score"] == config.SCORE_MAX
    assert "REASON_CONTEXT_MODEL_HIGH_RISK" in scam["reason_codes"]
    ok = play(bo_app, clock, "genuine", 92)
    assert "REASON_CONTEXT_MODEL_HIGH_RISK" not in ok["reason_codes"] and ok["risk_level"] == "ALLOW"

    # One admin can take it out of use at once.
    assert admin.call("post", f"/v1/bo/models/{mid}/retire")[0] == 200
    clock.now += 10
    assert play(bo_app, clock, "coached_scam", 93)["context_model"] is None
    actions = [a["action"] for a in admin.call("get", "/v1/bo/audit")[1]["audit"]]
    assert {"model_train", "model_request", "model_approve", "model_retire"} <= set(actions)


def test_a_new_challenger_replaces_the_old_one_and_is_compared_on_later_decisions(bo_app, admin, clock):
    history(bo_app, clock)
    _, page = admin.call("post", "/v1/bo/models/train")
    first = page["models"][0]["id"]
    admin.call("post", f"/v1/bo/models/{first}/request")
    second_admin(bo_app, admin).call("post", f"/v1/bo/models/{first}/approve")
    clock.now += 10
    _, page = admin.call("post", "/v1/bo/models/train")
    assert [(m["version"], m["status"]) for m in page["models"]] == [("ctx-2", "CHALLENGER"), ("ctx-1", "CHAMPION")]
    clock.now += 10
    for i in range(6):
        play(bo_app, clock, "remote_control", 300 + i, "FRAUD")
        play(bo_app, clock, "genuine", 400 + i)
    _, page = admin.call("get", "/v1/bo/models")
    cmp = page["comparison"]
    assert cmp["models"]["champion"]["version"] == "ctx-1" and cmp["models"]["challenger"]["version"] == "ctx-2"
    assert cmp["models"]["challenger"]["scored"] == 12 and cmp["models"]["challenger"]["fraud"] == 6
    assert cmp["models"]["challenger"]["fraud_caught"] >= 5 and cmp["models"]["challenger"]["genuine_flagged"] == 0
    _, page = admin.call("post", "/v1/bo/models/train")
    assert [m["status"] for m in page["models"]] == ["CHALLENGER", "RETIRED", "CHAMPION"]


def test_only_admins_train_and_viewers_can_read(bo_app, admin):
    assert admin.call("post", "/v1/bo/users", {"username": "ana", "password": "long-enough-pw", "role": "analyst"})[0] == 201
    ana = Portal(bo_app).login("ana", "long-enough-pw")
    assert ana.call("get", "/v1/bo/models")[0] == 200
    assert ana.call("post", "/v1/bo/models/train")[0] == 403
