import copy
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fortguard.app import DEV_API_KEY, create_app  # noqa: E402
from fortguard.client import InProcessTransport, enroll_device, run_session  # noqa: E402
from fortguard.generator import build_session  # noqa: E402
from fortguard.simdevice import SimDevice  # noqa: E402


@pytest.fixture(autouse=True)
def _restore_rules():
    """Rule edits through the back office change the shared config; put it back after each test."""
    from fortguard import config
    weights, bands = dict(config.WEIGHTS), {k: dict(v) for k, v in config.BANDS.items()}
    yield
    config.WEIGHTS.clear(); config.WEIGHTS.update(weights)
    config.BANDS.clear(); config.BANDS.update(bands)


class Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def app(clock):
    return create_app(clock=clock)


@pytest.fixture
def api(app):
    return InProcessTransport(app)


@pytest.fixture
def make_session(clock):
    def _make(scenario="genuine", seed=0, device=None):
        return build_session(scenario, int(clock() * 1000), seed, device=device)

    return _make


@pytest.fixture
def enrolled(api, make_session, clock):
    """A session whose device is already enrolled, with batches not yet sent."""

    def _enrolled(scenario="genuine", seed=0, level="STRONG"):
        session = make_session(scenario, seed)
        status, body = enroll_device(api, session["device"], int(clock() * 1000), level)
        assert status == 201, body
        return session

    return _enrolled


@pytest.fixture
def resign():
    """Sign a modified batch again with the device's own key, as the genuine device would."""

    def _resign(payload, session):
        return session["device"].sign(copy.deepcopy(payload))

    return _resign


__all__ = ["DEV_API_KEY", "SimDevice", "run_session"]
