"""Typing rhythm of the "Is it me?" sentence: usable samples, learning, accepting and refusing."""

import random

import pytest

from fortguard import config, rhythm
from fortguard.app import create_app


@pytest.fixture
def rhythms(clock):
    return create_app(clock=clock, admin_password="admin-test-password", dev_mode=True).fortguard_rhythms


def typed(gaps, field="other", start=1_000_000):
    keys, t = [{"event_type": "DOWN", "field": field, "ts": start, "inserted": 1}], start
    for g in gaps:
        t += int(g)
        keys.append({"event_type": "DOWN", "field": field, "ts": t, "inserted": 1})
    return keys


def person(seed, n=30):
    rng = random.Random(seed)
    return [rng.uniform(120, 420) for _ in range(n)]


def sample(pattern, seed, noise=0.12):
    rng = random.Random(seed)
    return [g * rng.lognormvariate(0, noise) for g in pattern]


def learn(rhythms, user, pattern, count=None):
    out = None
    for i in range(count or config.RHYTHM_MIN_SAMPLES):
        out = rhythms.judge(user, f"sess_learn{i:05d}", typed(sample(pattern, i)), 1_000 + i)
    return out


def test_gaps_are_read_from_the_sentence_field_only():
    keys = typed([200] * 14) + typed([90] * 20, field="amount", start=5_000_000)
    assert rhythm.gaps_of(keys) == [200] * 14


@pytest.mark.parametrize("spoil", [{"deleted": 1}, {"inserted": 2}])
def test_a_corrected_or_pasted_sample_cannot_be_compared(spoil):
    keys = typed([200] * 14)
    keys[5] = dict(keys[5], **spoil)
    assert rhythm.gaps_of(keys) is None


def test_a_very_short_sample_cannot_be_compared():
    assert rhythm.gaps_of(typed([200] * 5)) is None


def test_one_long_hesitation_is_capped():
    assert max(rhythm.gaps_of(typed([200] * 13 + [60_000]))) == config.RHYTHM_GAP_CAP_MS


def test_no_sentence_typing_means_no_rhythm_verdict(rhythms):
    assert rhythms.judge("usr_r0000001", "sess_r0000001", typed([200] * 14, field="amount"), 1) is None


def test_it_learns_first_and_counts(rhythms):
    me = person(1)
    first = rhythms.judge("usr_r0000001", "sess_a0000001", typed(sample(me, 0)), 1)
    assert first["verdict"] == "LEARNING" and first["sessions"] == 1 and "1 of 10" in first["text"]
    last = learn(rhythms, "usr_r0000001", me, count=config.RHYTHM_MIN_SAMPLES - 1)
    assert last["verdict"] == "LEARNING" and last["sessions"] == config.RHYTHM_MIN_SAMPLES


def test_the_owner_is_accepted_and_someone_else_is_refused(rhythms):
    me, other = person(1), person(2)
    learn(rhythms, "usr_r0000001", me)
    mine = rhythms.judge("usr_r0000001", "sess_mine0001", typed(sample(me, 99)), 5_000)
    theirs = rhythms.judge("usr_r0000001", "sess_other001", typed(sample(other, 99)), 5_001)
    assert mine["verdict"] == "OWNER_LIKELY" and mine["rhythm_distance"] <= mine["rhythm_limit"], mine
    assert theirs["verdict"] == "NOT_OWNER_LIKELY" and theirs["rhythm_distance"] > theirs["rhythm_limit"], theirs
    assert "distance" in theirs["text"] and theirs["method"] == "TYPING_RHYTHM"


def test_the_same_speed_with_a_different_pattern_is_refused(rhythms):
    """The fault this replaces: two people with the same average speed looked alike."""
    me = person(1)
    shuffled = me[:]
    random.Random(7).shuffle(shuffled)             # same gaps, so the same average, in a different order
    learn(rhythms, "usr_r0000001", me)
    assert rhythms.judge("usr_r0000001", "sess_other002", typed(sample(shuffled, 5)), 5_000)["verdict"] == "NOT_OWNER_LIKELY"


def test_a_refused_sample_is_not_learned_but_a_proved_owner_is(rhythms):
    me, other = person(1), person(2)
    learn(rhythms, "usr_r0000001", me)
    before = rhythms.count("usr_r0000001")
    rhythms.judge("usr_r0000001", "sess_other003", typed(sample(other, 1)), 5_000)
    assert rhythms.count("usr_r0000001") == before
    proved = rhythms.judge("usr_r0000001", "sess_other004", typed(sample(other, 2)), 5_001, owner_proved=True)
    assert proved["verdict"] == "OWNER_LIKELY" and rhythms.count("usr_r0000001") == before + 1


def test_an_unusable_sample_asks_for_another_try_and_is_not_learned(rhythms):
    keys = typed(sample(person(1), 0))
    keys[3] = dict(keys[3], deleted=1)
    out = rhythms.judge("usr_r0000001", "sess_bad00001", keys, 1)
    assert out["verdict"] == "UNKNOWN" and "without corrections" in out["text"]
    assert rhythms.count("usr_r0000001") == 0


def test_a_different_sentence_starts_learning_again(rhythms):
    learn(rhythms, "usr_r0000001", person(1, n=30))
    assert rhythms.judge("usr_r0000001", "sess_new00001", typed(sample(person(1, n=20), 0)), 9_000)["verdict"] == "LEARNING"


def test_erasing_a_customer_removes_the_rhythm(clock):
    app = create_app(clock=clock, admin_password="admin-test-password", dev_mode=True)
    learn(app.fortguard_rhythms, "usr_r0000001", person(1), count=3)
    app.fortguard_baselines.forget_user("usr_r0000001")
    assert app.fortguard_rhythms.count("usr_r0000001") == 0


def test_a_sentence_check_through_the_api(api, make_session):
    """A LOGIN evaluation whose session has sentence typing answers with the rhythm verdict."""
    import copy
    from fortguard.client import run_session
    s = make_session("genuine", 77)
    first = copy.deepcopy({k: v for k, v in s["batches"][0].items() if k != "signature"})
    first["key_events"] = typed([220] * 20, start=first["timestamp_ms"] - 20_000)
    s["batches"][0] = s["device"].sign(first)
    s["evaluate"].update(event_type="LOGIN")
    s["evaluate"].pop("transaction_details", None)
    status, body = run_session(api, s)
    assert status == 200 and body["risk_level"] == "ALLOW"
    assert body["identity"]["method"] == "TYPING_RHYTHM" and body["identity"]["verdict"] == "LEARNING"
    assert body["identity"]["sessions"] == 1
