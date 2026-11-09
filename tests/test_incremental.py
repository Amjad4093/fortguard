"""The incremental feature engine must give exactly what the full calculation gives."""

import copy
import math

import pytest

from fortguard import config
from fortguard.client import run_session
from fortguard.features import compute_features, compute_features_full
from fortguard.generator import SCENARIOS


def same(a, b):
    assert a.keys() == b.keys()
    for k in a:
        if a[k] is None or b[k] is None:
            assert a[k] is None and b[k] is None, k
        else:
            assert math.isclose(a[k], b[k], rel_tol=1e-9, abs_tol=1e-9), (k, a[k], b[k])


def stored(app, session):
    return app.fortguard_store.get(session["session_id"])


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("seed", range(6))
def test_incremental_equals_full_for_every_scenario(api, app, make_session, scenario, seed):
    session = make_session(scenario, seed)
    run_session(api, session)
    s = stored(app, session)
    if not s.consent_behavioral:
        assert s.fstate is None
        return
    # What scoring uses always equals the full calculation.
    same(compute_features(s), compute_features_full(s))
    if scenario == "remote_control":
        # laggy remote input arrives with timestamps out of order: the safe fallback is expected
        return
    assert s.fstate is not None and not s.fstate.stale
    same(s.fstate.features(), compute_features_full(s))


def test_a_swipe_split_across_batches_is_counted_once(api, app, enrolled, resign):
    session = enrolled("genuine", 1)
    b0, b1 = copy.deepcopy(session["batches"][0]), copy.deepcopy(session["batches"][1])
    # move the second half of the last gesture of batch 0 into the start of batch 1
    touch = b0["touch_events"]
    cut = max(i for i, e in enumerate(touch) if e["event_type"] == "DOWN") + 3
    b1["touch_events"] = touch[cut:] + b1["touch_events"]
    b0["touch_events"] = touch[:cut]
    assert api.post("/v1/telemetry/stream", resign(b0, session))[0] == 202
    assert api.post("/v1/telemetry/stream", resign(b1, session))[0] == 202
    s = stored(app, session)
    assert not s.fstate.stale
    same(s.fstate.features(), compute_features_full(s))


def test_out_of_order_batches_fall_back_to_the_full_calculation(api, app, enrolled):
    session = enrolled("genuine", 2)
    b0, b1 = session["batches"]
    assert api.post("/v1/telemetry/stream", b1)[0] == 202   # later batch first
    assert api.post("/v1/telemetry/stream", b0)[0] == 202
    s = stored(app, session)
    assert s.fstate.stale
    same(compute_features(s), compute_features_full(s))     # scoring still sees the right numbers


def test_out_of_order_scoring_matches_in_order_scoring(api, app, enrolled, clock):
    from fortguard.app import create_app
    from fortguard.client import InProcessTransport
    in_order = enrolled("coached_scam", 4)
    run_session(api, in_order, enroll=False)
    a = app.fortguard_decisions.snapshot()[0]
    other = create_app(clock=clock)
    api2 = InProcessTransport(other)
    from fortguard.client import enroll_device
    enroll_device(api2, in_order["device"], int(clock() * 1000))
    for batch in reversed(in_order["batches"]):
        api2.post("/v1/telemetry/stream", batch)
    api2.post("/v1/risk/evaluate", in_order["evaluate"], auth=True)
    b = other.fortguard_decisions.snapshot()[0]
    assert (a["risk_score"], a["reason_codes"]) == (b["risk_score"], b["reason_codes"])


def test_session_cap_keeps_state_and_events_in_step(api, app, enrolled, monkeypatch):
    monkeypatch.setattr(config, "MAX_EVENTS_PER_SESSION", 300)
    session = enrolled("genuine", 3)
    for b in session["batches"]:
        api.post("/v1/telemetry/stream", b)
    s = stored(app, session)
    assert s.event_count() == 300
    same(s.fstate.features(), compute_features_full(s))


def test_tremor_uses_the_same_recent_window_in_both_paths(api, app, enrolled, monkeypatch):
    monkeypatch.setattr(config, "TREMOR_WINDOW", 64)
    session = enrolled("genuine", 5)
    for b in session["batches"]:
        api.post("/v1/telemetry/stream", b)
    s = stored(app, session)
    assert len(s.fstate.accel_recent) == 64
    same(s.fstate.features(), compute_features_full(s))
